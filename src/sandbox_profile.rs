//! macOS SBPL sandbox profile generation.
//!
//! Builds a Seatbelt Profile Language string from [`SandboxConfig`],
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

use super::SandboxConfig;
use super::policy::{
    DENIED_CACHE_PREFIXES, DENIED_DOTFILES, DENIED_FILES, DENIED_HOME_SUBPATHS, EXEC_IN_WRITABLE,
    GPG_SIGNING_ALLOW_FILES, PROTECTED_IN_GITDIR, PROTECTED_IN_ROOT, PathBinDir, Protected,
    ResolvedToolDir, SENSITIVE_PROJECT_PATTERNS, SYSTEM_READ_FILES, TOOL_READ_DIRS,
    active_tool_dirs, app_dirs, escape_regex, nested_alternation, path_bin_dirs,
    playwright_runtime_intent, validate_playwright_socket_dir, validate_sbpl_path,
};

/// Generate a complete SBPL sandbox profile from the given options.
///
/// Sections are emitted in a fixed order — SBPL uses last-match-wins semantics,
/// so deny rules must come after their corresponding allows. Each `emit_*` helper
/// writes a contiguous block; their call order must not be changed.
pub fn generate_profile(config: &SandboxConfig, extra_git_dirs: &[PathBuf]) -> String {
    generate_profile_with_playwright_socket_dir(config, extra_git_dirs, None)
}

/// Generate an SBPL profile with one validated, cplt-owned Playwright socket base.
///
/// The path is kept separate from [`SandboxConfig`] because it is ephemeral per
/// process. It is honored only for exact Playwright runtime intent; callers must
/// validate it with `validate_playwright_socket_dir` before interpolation.
///
/// `extra_git_dirs` is the other macOS-only input `prepare` computes rather than
/// the caller supplying it: the resolved `.git` directories of writable grants
/// whose repo data does not live at `<grant>/.git` — a worktree, a bare repo, or
/// a grant pointing inside a repo (`discover::git_dir_of`). Deny-only: the
/// profile never *grants* access to them, it only places the protected-path
/// denies there so a sibling repo cannot be used for hook persistence (#212).
///
/// # Every path here is interpolated, not validated
///
/// This function does no SBPL-injection checking, on `extra_git_dirs` or on any
/// path in `config`. That is the module contract and predates this signature:
/// `sandbox::prepare` runs `validate_config_paths` and `validate_sbpl_path` over
/// every path — `extra_git_dirs` included — *before* calling in, and it is the
/// only production caller. Re-checking here cannot improve on that, because the
/// return type is a `String` with no error channel: a rejected path could only
/// be dropped silently, which fails open and is worse than not checking. Call
/// `prepare` rather than this directly; the `pub` is for unit tests that assert
/// on profile text.
pub fn generate_profile_with_playwright_socket_dir(
    config: &SandboxConfig,
    extra_git_dirs: &[PathBuf],
    playwright_socket_dir: Option<&Path>,
) -> String {
    let mut sb = String::with_capacity(4096);
    let home = config.home_dir.to_string_lossy();
    let project = config.project_dir.to_string_lossy();

    // Detect Chromium browser runtime: the user has opted in to executing
    // Playwright's Chromium binaries from ~/Library/Caches/ via allow_cache_exec.
    // When true, extra system-level permissions (syscall*, system-socket,
    // iokit-open-user-client, mach-register) are emitted for Chromium startup.
    // cplt also injects PLAYWRIGHT_MCP_SANDBOX=false for this explicit runtime
    // intent because Chromium cannot nest its own sandbox inside cplt's.
    //
    // Detection matches "ms-playwright" exactly or any subpath entry whose first
    // component is "ms-playwright" (e.g. "ms-playwright/chromium-<version>"). This
    // covers users who pin a specific versioned subdirectory in allow_cache_exec.
    // Substring matching (e.g. contains("playwright")) is intentionally avoided:
    // matching on the first path component prevents a rogue agent from escalating
    // privileges by creating a directory like "evil-ms-playwright-hook/".
    //
    // allow_cache_exec_any does NOT trigger these rules: it grants process-exec
    // broadly, but Chromium's extra IPC/syscall permissions should only be
    // emitted when the user explicitly signals browser testing intent.
    let allow_chromium_runtime =
        playwright_runtime_intent(config.allow_cache_exec, config.allow_cache_exec_any);
    let playwright_socket_dir =
        playwright_socket_dir.filter(|path| validate_playwright_socket_dir(path).is_ok());

    emit_header(&mut sb, &project);
    emit_process_rules(&mut sb);
    emit_project_access(&mut sb, &project);
    emit_home_access(
        &mut sb,
        &home,
        config.agent,
        config.agent_dirs,
        config.keychain_substitute.is_some(),
    );
    emit_git_hooks(&mut sb, config.git_hooks_path);
    emit_git_worktree(&mut sb, config.git_common_dir);
    emit_system_access(
        &mut sb,
        &home,
        config.allow_browser,
        allow_chromium_runtime,
        config.deny_clipboard,
    );
    emit_tool_dirs(
        &mut sb,
        config.home_dir,
        config.existing_home_tool_dirs,
        config.existing_app_dirs,
        config.agent,
        config.allow_cache_exec,
        config.allow_cache_exec_any,
    );
    emit_copilot_install(&mut sb, config.copilot_install_dir);
    emit_gradle_toolchain_exec(&mut sb, &home);
    emit_java_home(&mut sb, config.java_home);
    emit_dotnet_root(&mut sb, config.dotnet_root);
    emit_electron_app(&mut sb, config.electron_app_dir);
    emit_system_files(&mut sb);
    emit_temp_rules(
        &mut sb,
        config.allow_tmp_exec,
        config.allow_jvm_attach,
        config.allow_msbuild,
        config.scratch_dir,
        allow_chromium_runtime,
        allow_chromium_runtime
            .then_some(playwright_socket_dir)
            .flatten(),
    );
    emit_user_allows(
        &mut sb,
        config.extra_read,
        config.extra_write,
        config.extra_exec,
    );
    emit_deny_rules(&mut sb, &home, config.extra_deny);
    emit_registry_config_overrides(&mut sb, &home, config.extra_read);
    emit_denied_dotfile_overrides(
        &mut sb,
        &home,
        config.extra_read,
        config.extra_write,
        config.extra_exec,
    );
    emit_gpg_signing_rules(&mut sb, &home, config.allow_gpg_signing, config.extra_deny);
    emit_docker_rules(&mut sb, &home, config.allow_docker, config.extra_deny);
    emit_socket_rules(&mut sb, config.extra_socket, config.extra_deny);
    emit_network_rules(
        &mut sb,
        &home,
        config.extra_ports,
        config.allow_localhost_any,
        config.proxy_port,
        config.localhost_ports,
        config.proxy_forced,
    );
    // Sensitive project file denies MUST come after all user-configured allows.
    // SBPL uses last-match-wins, so a user allow like `allow.read = ["~/Repos"]`
    // would override the .env deny if emitted before it.
    emit_sensitive_project_denies(
        &mut sb,
        &project,
        config.extra_write,
        config.allow_env_files,
    );
    // Same reason, and one more: the worktree common-dir allow is emitted early
    // (so DENIED_DOTFILES still wins over it), which would leave its denies
    // reopenable by any later allow if they were emitted alongside it.
    emit_git_persistence_denies(
        &mut sb,
        &project,
        config.extra_write,
        config.git_common_dir,
        extra_git_dirs,
    );
    // Same reason, and the fix for the same bug one tree over: keeps the
    // agent's own auto-executing config unwritable even when a user
    // `allow.write` covers the whole config dir.
    emit_host_persistence_denies(&mut sb, config.agent, config.agent_dirs);
    // Same reason: keeps exec-allowed DOTNET_ROOT subtrees non-writable even
    // when a user allow.write covers them (write-then-exec).
    emit_dotnet_exec_denies(&mut sb, config.dotnet_root);
    // Same reason: keeps the exec-allowed Gradle toolchain dir non-writable
    // even when a user allow.write covers ~/.gradle (write-then-exec).
    emit_gradle_toolchain_write_deny(&mut sb, &home);
    // Same reason: the PATH-resolved bin and shim directories are already
    // read-only by construction (HOME_TOOL_DIRS grants write to the sibling
    // cache, not the parent), but a user allow.write covering ~/.bun or
    // $PNPM_HOME would reopen them, and mise's two live inside a tree that has
    // to stay writable.
    emit_path_bin_denies(&mut sb, config.home_dir);
    // Same reason, in the other direction: `process-exec` is granted
    // profile-wide, so an `allow.write` tree is executable unless something
    // says otherwise, and only a rule after every allow can say it.
    emit_user_write_exec_denies(
        &mut sb,
        &home,
        &project,
        config.extra_write,
        config.scratch_dir,
    );
    // MUST stay last: see `emit_exec_write_denies`. An exec grant that could be
    // reopened for writing by a later allow is a write-then-exec path.
    emit_exec_write_denies(&mut sb, config.extra_exec);

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

/// Writable roots whose git-persistence paths must be denied: the project plus
/// every `--allow-write` / `allow.write` grant, deduplicated, in that order.
///
/// #212: the denies used to carry a literal `{project}` prefix, so a sibling
/// repo granted via `allow.write` had a fully writable `.git/hooks` — and hooks
/// run *outside* the sandbox on the user's next git operation there.
///
/// Emitting the `{root}/.git/…` rules unconditionally (rather than only for
/// paths that are git repos today) is deliberate: it costs nothing for a
/// non-repo grant, and it covers a repo the agent creates mid-session with
/// `git init` **at the grant root itself**.
///
/// The path rules here cover the root only. Repositories nested *beneath* a
/// writable root — `~/work/proj/.git/hooks` under `--allow-write ~/work` — are
/// covered by `emit_nested_gitdir_denies` instead (#247), which is a regex and
/// therefore macOS only: on Linux that gap stays open outside bubblewrap, the
/// same limitation already documented for the root case.
fn writable_roots(project: &str, extra_write: &[PathBuf]) -> Vec<String> {
    let mut roots = vec![project.to_string()];
    for p in extra_write {
        let s = p.to_string_lossy().into_owned();
        if !roots.contains(&s) {
            roots.push(s);
        }
    }
    roots
}

fn emit_sensitive_project_denies(
    sb: &mut String,
    project: &str,
    extra_write: &[PathBuf],
    allow_env_files: bool,
) {
    // All security-critical project denies are emitted LAST in the profile.
    // SBPL uses last-match-wins, so these must come after all user-configured
    // allows (e.g. `allow.write = ["~/Repos"]`) to guarantee they cannot be
    // overridden by broad parent-path allows.

    let roots = writable_roots(project, extra_write);

    // Paths inside every writable root that must stay unwritable. The list is
    // [`PROTECTED_IN_ROOT`]; this only chooses the SBPL shape for each entry.
    // Paths *inside* a git directory are not here — they come from
    // [`PROTECTED_IN_GITDIR`] via `emit_gitdir_denies`, which runs later so no
    // user allow can reopen them.
    //
    // Emitted for EVERY writable root, not just the project (#212).
    for p in PROTECTED_IN_ROOT {
        let why = p.why;
        sbpl!(sb, ";; {why}");
        for root in &roots {
            emit_protected(sb, root, p);
            // A repo nested under a writable root needs this too: `allow.write
            // ~/code` leaves `~/code/other-repo/.agents/plugins` writable, and a
            // manifest there fires whichever agent next opens THAT repo.
            if p.nested {
                let r = escape_regex(root);
                let rel = escape_regex(p.rel);
                sbpl!(sb, "(deny file-write* (regex #\"^{r}/.+/{rel}($|/)\"))");
            }
        }
        sbpl!(sb);
    }

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

fn emit_home_access(
    sb: &mut String,
    home: &str,
    agent: Agent,
    agent_dirs: &[AgentDir],
    credential_outside_keychain: bool,
) {
    // Agent-specific directories from the Agent trait.
    // ~/.copilot used to be emitted by hand here, with its own `pkg` write-deny
    // sitting right after the allow. It is an ordinary `AgentDir` now, and `pkg`
    // is a `host_persistence_denies` entry emitted at the tail of the profile —
    // after `emit_user_allows`, so an `allow.write = ["~/.copilot"]` can no
    // longer silently reopen it the way it could here (#212, #256).
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
            // Writes on exec-only dirs (Pi's bin/, OpenCode's cache bin/) are
            // denied by emit_host_persistence_denies at the tail of the
            // profile, not here: a later user allow.write would otherwise
            // reopen them.
        }
        sbpl!(sb);
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
    // OpenCode stores its /connect credentials in its own data dir, and
    // third-party providers use env/config files — no Keychain needed.
    //
    // Dropped for this run when the agent's credential already came from the
    // environment (#242): the grant reaches every item in the login keychain
    // whose ACL lets `/usr/bin/security` through, not just the agent's own.
    if agent.needs_keychain() && !credential_outside_keychain {
        sbpl!(sb, ";; macOS Keychain (agent auth tokens)");
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
    // 4. mach-register — Chromium registers Mach services for IPC between
    //    browser, renderer, GPU, and Crashpad processes. The namespace is the
    //    build's bundle ID, not a fixed string: an upstream Chromium build uses
    //    org.chromium.*, while the Chrome for Testing build Playwright actually
    //    downloads uses com.google.chrome.for.testing.* (#263). The three
    //    narrowly scoped rules below are allowed; anything else cannot register.
    //    Crashpad's child_port_handshake uses bootstrap_check_in() which requires
    //    this permission; without it, EPERM (1100) cascades into a segfault.
    //    Scoped to ^org\.chromium\..+$ — the trailing \. prevents matching
    //    "org.chromiumevil" and the .+$ ensures at least one character follows
    //    (Chromium uses variable-depth subnamespaces like crashpad.*, Chromium.*).
    //    Playwright's Chrome for Testing also registers two exact namespaces:
    //    com.google.chrome.for.testing.MachPortRendezvousServer.<pid> and
    //    com.google.chrome.for.testing.apps.<user-data-dir-hash>. The first
    //    suffix accepts numeric PIDs only. The apps suffix is exactly the
    //    uppercase, 64-character hexadecimal SHA-256 of the user data directory.
    //    Denied registration produces EPERM (1100), so both regexes are fully
    //    anchored and limited to their observed suffix formats.
    //
    // SECURITY: these rules only activate when the user has explicitly opted in
    // to browser execution via allow_cache_exec containing "ms-playwright" or a
    // subpath like "ms-playwright/chromium-<version>" (first component must match
    // exactly).
    // syscall* is the broadest rule — Chrome uses undocumented Mach traps that
    // cannot be individually enumerated in a stable allowlist across OS versions.
    // iokit-open-user-client is unscoped because IOKit class names vary by GPU
    // hardware and macOS version; scoping would break on different machines.
    // system-socket is scoped to AF_UNIX — only Unix domain sockets, not TCP/UDP.
    // mach-register is limited to the anchored org.chromium.* namespace and the
    // two exact Chrome for Testing namespaces and suffix formats above,
    // preventing registration of arbitrary global Mach services.
    // Chrome helpers inherit cplt's Seatbelt profile and cannot reinitialize
    // Seatbelt inside it (`forbidden-sandbox-reinit`). Under explicit Playwright
    // runtime intent, cplt injects PLAYWRIGHT_MCP_SANDBOX=false unless the caller
    // explicitly passes that variable through. cplt remains the outer enforcing
    // boundary, but a compromised renderer then receives this complete opt-in
    // Chromium profile.
    if allow_chromium_runtime {
        sbpl!(
            sb,
            ";; Chromium browser runtime (Playwright headless testing)"
        );
        sbpl!(sb, "(allow syscall*)");
        sbpl!(sb, "(allow system-socket (socket-domain AF_UNIX))");
        sbpl!(sb, "(allow iokit-open-user-client)");
        // Separate rules rather than one loose pattern keep each literal
        // namespace and observed suffix format fully anchored.
        sbpl!(
            sb,
            r#"(allow mach-register (global-name-regex #"^org\.chromium\..+$"))"#
        );
        sbpl!(
            sb,
            r#"(allow mach-register (global-name-regex #"^com\.google\.chrome\.for\.testing\.MachPortRendezvousServer\.[0-9]+$"))"#
        );
        // Seatbelt does not match counted repetition here, so preserve the
        // exact SHA-256 length with 64 explicit uppercase-hex atoms.
        let apps_hash_pattern = "[0-9A-F]".repeat(64);
        sbpl!(
            sb,
            r#"(allow mach-register (global-name-regex #"^com\.google\.chrome\.for\.testing\.apps\.{apps_hash_pattern}$"))"#
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

    // Launch Services — a full sandbox escape, granted on purpose (#251).
    //
    // The flag exists for OAuth code flows (MCP servers, Antigravity, gh auth),
    // where the agent needs to hand an https URL to the user's browser. What it
    // actually grants is Launch Services, which starts the target through
    // launchd — outside this profile. So with the flag on, the agent can launch
    // any application on the machine, unsandboxed. `open -a Terminal script.sh`
    // is the whole exploit.
    //
    // Two things were checked before deciding not to shim `open` (#251):
    //
    // 1. `lsopen` cannot be scoped. SBPL gives it no filter — no URL, no bundle
    //    id, no path. Every profile under /System/Library/Sandbox/Profiles that
    //    uses it emits it bare, exactly as here; Apple has no narrower form to
    //    copy. It is all of Launch Services or none of it.
    //
    // 2. The grant does not run through the `open` binary, so a PATH wrapper of
    //    the kind `install_command_wrappers` installs for gh and git could not
    //    contain it. Measured on macOS 15 with a ~10-line C program linking
    //    CoreServices and calling LSOpenCFURLRef() on
    //    file:///System/Applications/Calculator.app, compiled outside and run
    //    inside a real cplt sandbox:
    //
    //      without --allow-browser:  status = -54, no application launched
    //      with    --allow-browser:  status =   0, Calculator running outside
    //                                             the sandbox
    //
    //    No `open` process was involved in either run. Separately, the blanket
    //    `(allow process-exec)` in `emit_process_rules` means /usr/bin/open is
    //    executable by absolute path anyway, which a PATH shim never sees.
    //
    // Both bypasses are one-liners for a hostile agent, so a shim would guard
    // only against an agent that types `open` politely. Do not add one and call
    // it a fix: the only control that holds is leaving the flag off.
    if allow_browser {
        sbpl!(
            sb,
            ";; Launch Services — unscopable; launches apps outside the sandbox"
        );
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
        "(allow file-read* (literal \"{home}/.gitconfig.local\"))"
    );
    sbpl!(
        sb,
        "(allow file-read* (literal \"{home}/.gitignore_global\"))"
    );
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
///
/// Only the *allows* live here. The matching denies are emitted at the very end
/// of the profile by [`emit_git_persistence_denies`]: SBPL is last-match-wins,
/// so denies placed here could be re-opened by a later user allow (a broad
/// `allow.write = ["~/Repos"]` covering the main repo would have done exactly
/// that).
fn emit_git_worktree(sb: &mut String, git_common_dir: Option<&Path>) {
    if let Some(common) = git_common_dir {
        let p = common.to_string_lossy();
        sbpl!(sb, ";; Git worktree shared directory");
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-write* (subpath \"{p}\"))");
        sbpl!(sb);
    }
}

/// Deny every path inside a git directory that names content git will later
/// execute or trust, for the project's own `.git` and for a worktree's shared
/// common dir.
///
/// Emitted LAST in the profile (last-match-wins), so no user allow can reopen it.
///
/// # Why the gitdir itself is denied
///
/// Every other rule here is a path *literal* or *subpath*. Path-shaped rules
/// only hold while the path keeps denoting the object it protects, and the
/// agent had write access to the gitdir's parent, so it could rename the whole
/// directory out from under them:
///
/// ```text
/// mv .git .gitbak                     # no rule names `.git` itself
/// > .gitbak/hooks/post-checkout       # no rule names `.gitbak/...`
/// >> .gitbak/config                   # core.hooksPath = /tmp/evilhooks
/// mv .gitbak .git                     # both files are now live
/// ```
///
/// `file-write-unlink` on the gitdir is what closes that: Seatbelt checks it on
/// the *source* of a rename and on unlink/rmdir, so the directory can no longer
/// be moved or removed, and the rules below keep meaning what they say. It does
/// not restrict writes *inside* the directory, so the index, refs, objects and
/// lock files all stay writable (verified with `sandbox-exec`).
///
/// `file-write-data` covers the worktree shape, where `<project>/.git` is a
/// gitdir *pointer file* rather than a directory: rewriting its contents would
/// aim the user's next git at an attacker-supplied gitdir. Directories are not
/// written through `write()`, so this rule is inert for a normal repo, and it
/// is not `file-write-create` — that would break `git init` in a project that
/// has no repo yet.
fn emit_gitdir_denies(sb: &mut String, gitdir: &str) {
    sbpl!(sb, ";; Git persistence prevention — {gitdir}");
    // Pins the name to the directory: no rename, no rmdir (see fn docs).
    sbpl!(sb, "(deny file-write-unlink (literal \"{gitdir}\"))");
    sbpl!(sb, "(deny file-write-data (literal \"{gitdir}\"))");
    // The names come from [`PROTECTED_IN_GITDIR`]; each entry's rationale lives
    // with it. This function only picks the SBPL shape.
    for p in PROTECTED_IN_GITDIR {
        emit_protected(sb, gitdir, p);
    }
    sbpl!(sb);
}

/// Emit one [`Protected`] entry as an SBPL write-deny under `base`.
///
/// The only per-backend decision: a tree becomes a `subpath` rule, a file a
/// `literal` one.
fn emit_protected(sb: &mut String, base: &str, p: &Protected) {
    let rel = p.rel;
    if p.tree {
        sbpl!(sb, "(deny file-write* (subpath \"{base}/{rel}\"))");
    } else {
        sbpl!(sb, "(deny file-write* (literal \"{base}/{rel}\"))");
    }
}

/// All git-directory denies, emitted last so no earlier allow can reopen them.
///
/// #212: emitted for the project's `.git` **and** for every `allow.write`
/// grant's `.git`, plus the resolved gitdir of any root whose repo data does
/// not live at `<root>/.git` — a worktree, a bare repo, or a grant pointing
/// inside a repo (see `discover::git_dir_of`). A granted sibling repo is as
/// much a persistence vector as the project: hooks planted there run outside
/// the sandbox on the user's next git operation in that repo.
///
/// `<root>/.git` is emitted for every writable root unconditionally, even one
/// that is not a repo today, so a repo the agent creates mid-session with
/// `git init` at the grant root is covered too.
/// Write-denies the agent's own host-persistence paths, plus writes on any
/// exec-only agent dir.
///
/// The paths come from [`Agent::host_persistence_paths`]: files inside a
/// writable agent config dir that auto-execute on the HOST the next time the
/// agent runs outside the sandbox — hooks, extensions, plugins, installed
/// package code — which the agent never needs to write mid-session.
///
/// **Emitted at the tail of the profile, after `emit_user_allows`, and that
/// placement is the whole point.** SBPL is last-match-wins, so while these
/// lived next to the dir-wide allow in `emit_home_access` a user
/// `allow.write = ["~/.gemini"]` (or `["~/.claude"]`) silently reopened every
/// one of them — the same bug #212 fixed for the git-persistence denies by
/// moving them here. `is_unsafe_root` only rejects `~` itself, so a
/// whole-config-dir grant is an ordinary thing for a user to write.
///
/// The consequence is that there is no `allow.write` escape hatch for these
/// paths any more: a first-run login that needs to write a denied file has to
/// happen outside cplt (see `Agent::login_warning`, which says so up front).
///
/// Applies to every writable grant rather than the first one: Claude's default
/// layout grants both `~/.claude` (the data dir these subpaths live under) and
/// the `~/.claude.json` file, and we must not depend on their ordering. A deny
/// on a file grant (`~/.claude.json/statusline.sh`) can never match a real
/// path, so it is a harmless no-op; the deny on the data dir is what matters.
/// Same for Antigravity's two grants, whose entries belong to one dir each.
///
/// macOS only — Landlock cannot deny a subpath within an allowed dir, so on
/// Linux the bubblewrap read-only overlay carries this (see SECURITY.md).
fn emit_host_persistence_denies(sb: &mut String, agent: Agent, agent_dirs: &[AgentDir]) {
    let paths = agent.host_persistence_paths(agent_dirs);
    let exec_only = agent_dirs.iter().filter(|d| !d.write && d.process_exec);
    let mut wrote_header = false;
    for path in paths
        .iter()
        .map(|p| p.display().to_string())
        .chain(exec_only.map(|d| d.path.display().to_string()))
    {
        if !wrote_header {
            sbpl!(sb, ";; Agent config-dir host-persistence denies");
            wrote_header = true;
        }
        sbpl!(sb, "(deny file-write* (subpath \"{path}\"))");
    }
    if wrote_header {
        sbpl!(sb);
    }
}

fn emit_git_persistence_denies(
    sb: &mut String,
    project: &str,
    extra_write: &[PathBuf],
    git_common_dir: Option<&Path>,
    extra_git_dirs: &[PathBuf],
) {
    let mut gitdirs: Vec<String> = writable_roots(project, extra_write)
        .iter()
        .map(|root| format!("{root}/.git"))
        .collect();
    for dir in git_common_dir
        .map(|c| c.to_string_lossy().into_owned())
        .into_iter()
        .chain(
            extra_git_dirs
                .iter()
                .map(|d| d.to_string_lossy().into_owned()),
        )
    {
        if !gitdirs.contains(&dir) {
            gitdirs.push(dir);
        }
    }
    for gitdir in &gitdirs {
        emit_gitdir_denies(sb, gitdir);
    }
    // `<gitdir>/worktrees/<name>/config.worktree` is read as repository config
    // when `extensions.worktreeConfig` is set, so it is another core.hooksPath
    // vector — one per worktree. `<name>` is unknown when the profile is
    // generated and SBPL subpaths have no wildcard, so this matches by suffix
    // instead. Denying `worktrees/` wholesale is not an option: `git worktree
    // add` and every operation inside a worktree write HEAD, index and logs
    // there. Nothing legitimate writes this file from inside the sandbox —
    // `git config --worktree` first needs `extensions.worktreeConfig`, which is
    // a denied `<gitdir>/config` write.
    //
    // `<gitdir>/worktrees/<name>/commondir` is NOT denied, deliberately. It is
    // the same steering primitive as the top-level `commondir` above, but `git
    // worktree add` writes exactly this file (containing `../..`) for every
    // worktree it creates, so denying it would break a command that has to keep
    // working. `discover::git_common_dir` rejects a steered value, which closes
    // the escalation without costing that; the top-level `commondir` deny is
    // free only because nothing legitimate ever writes it.
    sbpl!(sb, ";; Per-worktree git config (core.hooksPath vector)");
    sbpl!(sb, "(deny file-write* (regex #\"/config\\.worktree$\"))");
    sbpl!(sb);

    for root in writable_roots(project, extra_write) {
        emit_nested_gitdir_denies(sb, &root);
    }
}

/// Extend the git-persistence denies to repositories nested *beneath* a
/// writable root (#247).
///
/// `emit_gitdir_denies` names paths, so it can only cover gitdirs known when
/// the profile is generated: the project's own, and `<root>/.git` for every
/// writable root. With `--project-dir ~/code`, or an `allow.write` on a
/// directory that contains repositories, `~/code/other-repo/.git/hooks/…` stayed
/// writable — and hooks planted there run outside the sandbox on the user's next
/// git operation in that repo. A path rule cannot express "any depth", so this
/// is the one place a regex earns its keep.
///
/// The alternation is derived from `PROTECTED_IN_GITDIR`, so it cannot drift
/// from what `emit_gitdir_denies` emits — with `($|/)` so the directory entry itself is
/// covered too (otherwise the agent could plant a *symlink* named `hooks`
/// pointing at a writable directory). `file-write-unlink` and `file-write-data`
/// on the `.git` entry close the rename-away trick and the worktree pointer-file
/// rewrite, for the same reasons spelled out on `emit_gitdir_denies`.
///
/// Deliberately narrow: the leading `.+/` means the root's own `.git` is not
/// matched here (it already has the stronger literal rules), and nothing outside
/// a path component spelled exactly `.git` can match — `.github/workflows` does
/// not, because `\.git/` requires the separator immediately after `.git`.
/// Ordinary work inside a nested repo — source files, build output, and every
/// git internal except the four names above — is untouched.
///
/// Cost: `git clone` and `git init` into a nested directory now fail on their
/// `.git/config` write. That is the same trade already accepted at the root, and
/// the alternative is leaving hook execution open.
///
/// macOS only. Landlock cannot deny a subpath inside an allowed tree, so on
/// Linux this gap stays open outside bubblewrap — the same limitation already
/// documented for the root case. Nothing here implies Linux coverage.
fn emit_nested_gitdir_denies(sb: &mut String, root: &str) {
    let r = escape_regex(root);
    // Derived from [`PROTECTED_IN_GITDIR`] rather than written out, so the
    // alternation cannot drift from the table the way a hand-copied list did.
    let names = nested_alternation(PROTECTED_IN_GITDIR);
    sbpl!(
        sb,
        ";; Git persistence prevention — repos nested under {root}"
    );
    sbpl!(
        sb,
        "(deny file-write* (regex #\"^{r}/.+/\\.git/({names})($|/)\"))"
    );
    sbpl!(sb, "(deny file-write-unlink (regex #\"^{r}/.+/\\.git$\"))");
    sbpl!(sb, "(deny file-write-data (regex #\"^{r}/.+/\\.git$\"))");
    sbpl!(sb);
}

fn emit_tool_dirs(
    sb: &mut String,
    home_dir: &std::path::Path,
    existing_home_tool_dirs: Option<&[ResolvedToolDir]>,
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
    let active_dirs = active_tool_dirs(home_dir, existing_home_tool_dirs);

    for ResolvedToolDir { path, dir } in &active_dirs {
        let p = path.to_string_lossy();
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        if dir.process_exec {
            sbpl!(sb, "(allow process-exec (subpath \"{p}\"))");
        }
        if dir.map_exec {
            sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        }
        if dir.write {
            sbpl!(sb, "(allow file-write* (subpath \"{p}\"))");
        }
    }
    // Deny exec from writable dirs that should not have it.
    // Must come AFTER allows (last-match-wins in Seatbelt).
    // The blanket (allow process-exec) means we need explicit denies,
    // not just absence of a per-dir allow.
    for ResolvedToolDir { path, dir } in &active_dirs {
        let p = path.to_string_lossy();
        if dir.write && !dir.process_exec {
            sbpl!(sb, "(deny process-exec (subpath \"{p}\"))");
        }
        if dir.write && !dir.map_exec {
            sbpl!(sb, "(deny file-map-executable (subpath \"{p}\"))");
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

/// Allow executing JDKs that Gradle auto-provisions into `~/.gradle/jdks`.
///
/// `~/.gradle` is a dependency store in `HOME_TOOL_DIRS` (write + map-exec, no
/// process-exec), so `emit_tool_dirs` emits an explicit
/// `(deny process-exec (subpath "~/.gradle"))` to beat the blanket
/// `(allow process-exec)`. That is right for dependency JARs, but Gradle's
/// toolchain support drops provisioned JDKs under `~/.gradle/jdks` — inside the
/// denied subtree. Forking a toolchain `javac` or test JVM then fails with
/// "Operation not permitted", and no config key could grant it (`allow.read`
/// emits `file-read*` only, and there is no `allow.exec`). Re-allow exec for
/// just that subtree; the matching write-deny is emitted later, by
/// `emit_gradle_toolchain_write_deny`.
///
/// Emitted AFTER `emit_tool_dirs` because SBPL is last-match-wins.
fn emit_gradle_toolchain_exec(sb: &mut String, home: &str) {
    sbpl!(sb, ";; Gradle toolchain JDKs — exec auto-provisioned JDKs");
    sbpl!(sb, "(allow process-exec (subpath \"{home}/.gradle/jdks\"))");
    sbpl!(sb);
}

/// Keep the exec-allowed Gradle toolchain directory read-only.
///
/// `~/.gradle` is agent-writable, so exec inside it without a write-deny is a
/// write-then-exec primitive: drop a binary into `~/.gradle/jdks` and run it,
/// bypassing the `allow_tmp_exec` / `allow_cache_exec` gates entirely. Gradle
/// provisions toolchains outside the sandbox, so this costs nothing in normal
/// use. The trade: with `auto-download=true`, a toolchain not already on disk
/// now fails at provisioning time with a write error instead of at exec time
/// with EPERM. Provision it outside cplt, or point
/// `org.gradle.java.installations.paths` at a JDK outside `~/.gradle`.
///
/// Emitted AFTER `emit_user_allows` because SBPL is last-match-wins: a user
/// `allow.write` covering `~/.gradle` (or any parent) would otherwise override
/// a write-deny emitted alongside the exec allow and silently reopen the hole.
/// Same rationale as `emit_dotnet_exec_denies`.
fn emit_gradle_toolchain_write_deny(sb: &mut String, home: &str) {
    sbpl!(
        sb,
        ";; Gradle toolchain JDKs — exec-allowed path stays read-only"
    );
    sbpl!(sb, "(deny file-write* (subpath \"{home}/.gradle/jdks\"))");
    sbpl!(sb);
}

/// Allow executing the dotnet host and loading .NET SDK libraries from DOTNET_ROOT.
/// Needed when the SDK is installed outside TOOL_READ_DIRS — e.g.
/// actions/setup-dotnet's ~/hostedtoolcache, or dotnet-install.sh into a
/// custom directory under $HOME.
fn emit_dotnet_root(sb: &mut String, dotnet_root: Option<&Path>) {
    if let Some(dir) = dotnet_root {
        let p = dir.to_string_lossy();
        sbpl!(
            sb,
            ";; DOTNET_ROOT — dotnet host exec + SDK read/dylib loading"
        );
        sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        // DOTNET_ROOT may be ~/.dotnet, whose writable CLI-state rule denies
        // process execution. Re-allow only the trusted host; the matching
        // write-deny is emitted later, by `emit_dotnet_exec_denies`.
        sbpl!(sb, "(allow process-exec (literal \"{p}/dotnet\"))");
        // `dotnet build` doesn't just run the top-level host — MSBuild forks
        // out-of-proc compiler workers straight out of the SDK install, e.g.
        // {p}/sdk/<ver>/Roslyn/bincore/csc and VBCSCompiler, plus apphost
        // templates copied out of {p}/sdk and {p}/shared. Without exec on
        // these subtrees, `dotnet build` gets past restore/host-launch and
        // then fails with "Operation not permitted" the moment MSBuild tries
        // to spawn csc. Scoped to sdk/shared (not the whole DOTNET_ROOT) so
        // CLI state files written directly under ~/.dotnet (telemetry
        // sentinel, tool manifests) keep their normal write access.
        for subdir in ["sdk", "shared"] {
            sbpl!(sb, "(allow process-exec (subpath \"{p}/{subdir}\"))");
        }
        sbpl!(sb);
    }
}

/// Keep every exec-allowed DOTNET_ROOT subtree read-only.
///
/// These paths are the only ones where cplt re-grants `process-exec` inside a
/// tree that is otherwise writable, so write access to them is a
/// write-then-exec primitive: drop a binary into `$DOTNET_ROOT/sdk` and run
/// it, bypassing the `allow_tmp_exec` / `allow_cache_exec` gates entirely.
///
/// Emitted AFTER `emit_user_allows` because SBPL is last-match-wins: a user
/// `allow.write` covering DOTNET_ROOT (e.g. `allow.write = ["~/.dotnet"]`, or
/// any parent of it) would otherwise override a write-deny emitted alongside
/// the exec allows and silently reopen the hole. Same rationale as
/// `emit_sensitive_project_denies`.
fn emit_dotnet_exec_denies(sb: &mut String, dotnet_root: Option<&Path>) {
    if let Some(dir) = dotnet_root {
        let p = dir.to_string_lossy();
        sbpl!(sb, ";; DOTNET_ROOT — exec-allowed paths stay read-only");
        sbpl!(sb, "(deny file-write* (literal \"{p}/dotnet\"))");
        for subdir in ["sdk", "shared"] {
            sbpl!(sb, "(deny file-write* (subpath \"{p}/{subdir}\"))");
        }
        sbpl!(sb);
    }
}

/// Write-deny every directory that lands on the user's `PATH` ahead of
/// `/usr/bin`.
///
/// A file written to one of these outlives the session: the user's next
/// unsandboxed `git`, `node` or `python` resolves through PATH and runs it.
/// `~/.cargo/bin` has been read-only for exactly this reason; these are the
/// rest of the class — `~/.bun/bin`, `~/.deno/bin`, `$PNPM_HOME`, and mise's
/// `shims/` and `installs/`.
///
/// Most of them are read-only by construction already, because
/// `HOME_TOOL_DIRS` grants write to the sibling cache instead of the parent
/// (that shape, unlike a deny, also holds on Landlock). Re-denying them here
/// is what survives a user `allow.write = ["~/.bun"]`. mise is the exception
/// that genuinely needs the deny: `shims/` and `installs/` sit inside the mise
/// data dir, which has to stay writable for the rest of mise's state.
///
/// Emitted AFTER `emit_user_allows` because SBPL is last-match-wins — same
/// rationale as `emit_host_persistence_denies`.
///
/// The cost is deliberate: `bun install -g`, `deno install`, `pnpm add -g`,
/// `mise use -g`, `mise install` and `mise upgrade` all fail inside the
/// sandbox, and a repo
/// whose `mise.toml` pins a toolchain the host does not already have no longer
/// bootstraps. See docs/known-impacts.md.
///
/// macOS only. Landlock cannot deny a subpath inside an allowed tree, so on
/// Linux the mise pair is carried by the bubblewrap read-only overlay
/// (`policy::mise_ro_protect_paths`) and the rest by the `HOME_TOOL_DIRS`
/// shape; the `TopLevel` shape has no Landlock equivalent at all for a
/// relocated `XDG_DATA_HOME`. See docs/security.md.
fn emit_path_bin_denies(sb: &mut String, home_dir: &Path) {
    sbpl!(sb, ";; PATH-resolved bin/shim dirs stay read-only");
    for dir in path_bin_dirs(home_dir) {
        match dir {
            PathBinDir::Subtree(path) => {
                if validate_sbpl_path(&path).is_err() {
                    continue;
                }
                let p = path.display();
                sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
            }
            // Anchored to a single path component so `store/` and everything
            // under it keeps its write grant.
            PathBinDir::TopLevel(path) => {
                if validate_sbpl_path(&path).is_err() {
                    continue;
                }
                let r = escape_regex(&path.to_string_lossy());
                sbpl!(sb, "(deny file-write* (regex #\"^{r}/[^/]+$\"))");
            }
        }
    }
    sbpl!(sb);
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
    allow_msbuild: bool,
    scratch_dir: Option<&Path>,
    allow_chromium_runtime: bool,
    playwright_socket_dir: Option<&Path>,
) {
    sbpl!(sb, ";; Temp directories");
    sbpl!(sb, "(allow file-read* (subpath \"/private/tmp\"))");
    sbpl!(sb, "(allow file-write* (subpath \"/private/tmp\"))");
    sbpl!(sb, "(allow file-read* (subpath \"/private/var/folders\"))");
    sbpl!(sb, "(allow file-write* (subpath \"/private/var/folders\"))");
    if let Some(socket_dir) = playwright_socket_dir {
        let socket_path = socket_dir.to_string_lossy();
        // SECURITY: this grants only AF_UNIX operations below the one random,
        // cplt-owned directory validated before profile generation. The
        // existing /private/tmp file rules are sufficient; no temp execution
        // or additional file permission accompanies this capability.
        sbpl!(sb, ";; Per-session Playwright control sockets");
        sbpl!(
            sb,
            "(allow network-bind (local unix-socket (subpath \"{socket_path}\")))"
        );
        sbpl!(
            sb,
            "(allow network-inbound (local unix-socket (subpath \"{socket_path}\")))"
        );
        sbpl!(
            sb,
            "(allow network-outbound (remote unix-socket (subpath \"{socket_path}\")))"
        );
        sbpl!(sb);
    }
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
    if allow_msbuild {
        // Allow Unix domain socket operations for MSBuild worker-node IPC.
        //
        // `dotnet build` forks out-of-proc worker nodes that communicate with
        // the client over a Unix domain socket at /private/tmp/MSBuild<pid>
        // (see NamedPipeUtil.GetPlatformSpecificPipeName in the MSBuild source).
        //
        // This is NOT the persistent MSBuild Server: that feature uses a
        // differently-named socket, /private/tmp/MSBuildServer-<hash> (see
        // MSBuild-Server.md's "pipe name convention"), which the regex below
        // does not match and which therefore remains blocked. Reuse of a
        // persistent server — including one started outside this sandbox — is
        // additionally disabled by setting DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER=1
        // (see sandbox_env.rs), so `dotnet build` never attempts to create or
        // connect to that server pipe in the first place.
        //
        // All three socket operations are required (same pattern as JVM attach):
        //   - network-bind:    the worker node creates the socket
        //   - network-inbound: the worker node accepts client connections
        //   - network-outbound: the client connects to the socket
        //
        // SECURITY: regex is anchored with ^ and $ to the exact MSBuild<pid>
        // filename directly under /private/tmp — this does not grant broad
        // /private/tmp socket access (SSH_AUTH_SOCK etc. remain unaffected).
        for op in &[
            r#"(allow network-bind (local unix-socket (regex #"^/private/tmp/MSBuild[0-9]+$")))"#,
            r#"(allow network-inbound (local unix-socket (regex #"^/private/tmp/MSBuild[0-9]+$")))"#,
            r#"(allow network-outbound (remote unix-socket (regex #"^/private/tmp/MSBuild[0-9]+$")))"#,
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

fn emit_user_allows(
    sb: &mut String,
    extra_read: &[PathBuf],
    extra_write: &[PathBuf],
    extra_exec: &[PathBuf],
) {
    if !extra_read.is_empty() || !extra_write.is_empty() || !extra_exec.is_empty() {
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
        // `process-exec` is granted profile-wide, so an exec grant needs the two
        // rights that are not: reading the binary and its interpreter, and
        // mapping the pages executable. The matching write-deny is emitted last,
        // by `emit_exec_write_denies`.
        for path in extra_exec {
            let p = path.to_string_lossy();
            sbpl!(sb, "(allow file-read* (subpath \"{p}\"))");
            sbpl!(sb, "(allow file-map-executable (subpath \"{p}\"))");
        }
        sbpl!(sb);
    }
}

/// Keep every `allow.exec` tree read-only.
///
/// `sandbox::prepare` already refuses an exec grant that overlaps the project
/// dir or an `allow.write` grant, so this is the second line: nothing else in
/// the profile — a tool dir, a scratch path, an agent dir — may quietly make an
/// exec-granted tree writable either.
///
/// Emitted LAST, after every allow in the profile. SBPL is last-match-wins, so
/// a write-deny sitting next to its own allow is reopened by any later
/// `file-write*` allow that covers the same tree. That is exactly the bug #158
/// left behind, and the reason `emit_dotnet_exec_denies` and
/// `emit_gradle_toolchain_write_deny` are at the bottom of `generate_profile`
/// too. Do not move this call.
fn emit_exec_write_denies(sb: &mut String, extra_exec: &[PathBuf]) {
    if extra_exec.is_empty() {
        return;
    }
    sbpl!(sb, ";; allow.exec trees stay read-only (write-then-exec)");
    for path in extra_exec {
        let p = path.to_string_lossy();
        sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
    }
    sbpl!(sb);
}

/// Keep every `allow.write` tree non-executable.
///
/// `process-exec` is granted profile-wide (`emit_process_rules`), so a user
/// write grant lands on a tree the kernel will already execute from: writable
/// plus executable, which is the binary-drop staging pair `validate_exec_grants`
/// refuses when an `allow.exec` grant creates it the other way round (#295).
/// `HOME_TOOL_DIRS` entries have carried the compensating deny since long
/// before `allow.write` existed; user grants never did (#243).
///
/// Emitted after every allow, for the reason `emit_exec_write_denies` spells
/// out: SBPL is last-match-wins.
///
/// Three exec grants are re-issued afterwards, but only where they fall inside
/// a granted tree — an unconditional re-allow would override the `/private/tmp`
/// exec deny for a project or scratch dir that lives there:
///
/// - the project directory, which is writable and executable by design, and
///   which an `allow.write` on a parent (`~/Repos`) would otherwise silently
///   stop running its own build output;
/// - the scratch dir, which is write+exec by design;
/// - the [`EXEC_IN_WRITABLE`] trees, which were already write+execute before
///   the grant. The deny exists to stop a grant *creating* that pair, not to
///   revoke a documented one.
///
/// Everything else loses execute: an `allow.write` covering `~/.cargo` or
/// `~/.rustup` makes a read-only tool tree writable, and that pair is new.
fn emit_user_write_exec_denies(
    sb: &mut String,
    home: &str,
    project: &str,
    extra_write: &[PathBuf],
    scratch_dir: Option<&Path>,
) {
    if extra_write.is_empty() {
        return;
    }
    sbpl!(
        sb,
        ";; allow.write trees stay non-executable (write-then-exec)"
    );
    for path in extra_write {
        let p = path.to_string_lossy();
        sbpl!(sb, "(deny process-exec (subpath \"{p}\"))");
    }
    let granted = |p: &Path| extra_write.iter().any(|w| p.starts_with(w));
    let mut carve_outs: Vec<PathBuf> = vec![PathBuf::from(project)];
    carve_outs.extend(scratch_dir.map(Path::to_path_buf));
    carve_outs.extend(
        EXEC_IN_WRITABLE
            .iter()
            .filter(|e| e.macos)
            .map(|e| Path::new(home).join(e.path)),
    );
    for path in carve_outs.iter().filter(|p| granted(p)) {
        if validate_sbpl_path(path).is_err() {
            continue;
        }
        let p = path.display();
        sbpl!(sb, "(allow process-exec (subpath \"{p}\"))");
    }
    sbpl!(sb);
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
    // These files must stay read-only even when an overlapping path is writable
    // (for example a temporary HOME under /private/var/folders).
    for file in [
        ".gitconfig",
        ".gitconfig.local",
        ".gitignore_global",
        ".config/git/config",
    ] {
        sbpl!(sb, "(deny file-write* (literal \"{home}/{file}\"))");
    }
    for path in extra_deny {
        let p = path.to_string_lossy();
        sbpl!(sb, "(deny file-read* (subpath \"{p}\"))");
        sbpl!(sb, "(deny file-write* (subpath \"{p}\"))");
    }
    sbpl!(sb);
}

/// Resolve symlinks in a path built from `$HOME`, falling back to the path
/// itself when it does not exist.
///
/// `extra_read` / `extra_write` entries are already canonicalized (`--allow-read`
/// through `canonicalize_paths`, config `allow.read` through
/// `resolve_config_path`), so any comparison against a path we construct from
/// `$HOME` must resolve that side too. Without it a dotfile-managed home — where
/// `~/.npmrc` is a symlink into `~/dotfiles` — never matches, and the user's
/// explicit grant is silently dropped.
fn resolved(path: PathBuf) -> PathBuf {
    std::fs::canonicalize(&path).unwrap_or(path)
}

/// Re-allow credential files from `DENIED_HOME_SUBPATHS` when the user
/// explicitly opts in via `--allow-read` or `allow.read` in config.toml.
///
/// Emitted AFTER `emit_deny_rules` so SBPL last-match-wins re-allows the file.
/// Only matches exact paths from `DENIED_HOME_SUBPATHS` — hard denies
/// (DENIED_FILES, DENIED_DOTFILES) cannot be overridden this way.
///
/// The re-allow names the `$HOME` path, not the resolved one: the deny it
/// overrides names `$HOME` too, and the macOS sandbox matches a rule against
/// the path as opened, so the literal has to line up with the deny. The
/// resolved target is separately allowed by `emit_user_allows`.
fn emit_registry_config_overrides(sb: &mut String, home: &str, extra_read: &[PathBuf]) {
    let home_path = Path::new(home);
    let mut overrides: Vec<&str> = Vec::new();

    for &file in DENIED_HOME_SUBPATHS {
        let full_path = resolved(home_path.join(file));
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

/// Every spelling of `path` that needs a re-allow, when it names a path *inside*
/// a [`DENIED_DOTFILES`] directory. Empty when it does not.
///
/// A grant naming the directory itself is not an override — `sandbox::prepare`
/// refuses it outright (#291), and honouring it here would reopen a whole
/// credential directory on the strength of one config line.
fn denied_dotfile_override_paths(home: &Path, path: &Path) -> Vec<String> {
    for &dotfile in DENIED_DOTFILES {
        let denied_dir = home.join(dotfile);
        let resolved_dir = resolved(denied_dir.clone());
        let Ok(rel) = path.strip_prefix(&resolved_dir) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            return Vec::new();
        }
        let mut forms = vec![path.to_string_lossy().into_owned()];
        // When `~/<dotfile>` is itself a symlink the deny names the $HOME
        // path, and the macOS sandbox matches a rule against the path as
        // opened — so the re-allow has to cover that form as well.
        if resolved_dir != denied_dir {
            forms.push(denied_dir.join(rel).to_string_lossy().into_owned());
        }
        return forms;
    }
    Vec::new()
}

/// Re-allow specific files inside DENIED_DOTFILES directories when the user
/// has explicitly approved them via `allow.read` or `allow.write`.
///
/// DENIED_DOTFILES uses `(deny file-read* (subpath ...))` and the matching
/// `file-write*` deny, which block entire directories. When a user explicitly
/// approves a file inside one of these dirs, we emit a targeted
/// `(allow ... (literal ...))` AFTER the deny so SBPL last-match-wins grants
/// access to that specific file only.
///
/// A write grant gets read as well, matching [`emit_user_allows`]: a write
/// grant that cannot read the file it writes is not a usable grant. That is
/// what makes `~/.ssh/known_hosts` appendable, which stock `ssh` needs on a
/// first connection under the default `StrictHostKeyChecking`. Before this,
/// `emit_user_allows` emitted the write grant *before* `emit_deny_rules`, the
/// deny won, and the grant silently did nothing on macOS while working on
/// Linux — the same shape as #291, pointing the other way.
///
/// `allow.exec` is here for the same reason and needs the same two rights
/// `emit_user_allows` grants it: reading the binary and mapping it executable.
/// Without this it was emitted before the deny and lost to it, so
/// `allow.exec = ["~/.docker/cli-plugins"]` — a real layout, alongside
/// `~/.terraform.d/plugins` — worked on Linux and silently did not on macOS.
/// The write-deny `emit_exec_write_denies` puts at the tail of the profile
/// still applies, so an exec grant here does not become writable.
///
/// The re-allows use `subpath`, not `literal`. `literal` matches the directory
/// entry and nothing beneath it, so a grant on a subdirectory of a credential
/// dir — `~/.aws/sso/cache`, `~/.kube/cache` — was accepted, granted the whole
/// subtree by Landlock's `path_beneath`, and granted effectively nothing on
/// macOS. `subpath` matches a plain file exactly as `literal` did, so the
/// file case is unchanged and the directory case now means the same thing on
/// both backends: the subtree the user named.
fn emit_denied_dotfile_overrides(
    sb: &mut String,
    home: &str,
    extra_read: &[PathBuf],
    extra_write: &[PathBuf],
    extra_exec: &[PathBuf],
) {
    let home_path = Path::new(home);
    // A path granted both ways is emitted once, from the write list.
    let read_only: Vec<String> = extra_read
        .iter()
        .filter(|p| !extra_write.contains(p) && !extra_exec.contains(p))
        .flat_map(|p| denied_dotfile_override_paths(home_path, p))
        .collect();
    let writable: Vec<String> = extra_write
        .iter()
        .flat_map(|p| denied_dotfile_override_paths(home_path, p))
        .collect();
    let executable: Vec<String> = extra_exec
        .iter()
        .flat_map(|p| denied_dotfile_override_paths(home_path, p))
        .collect();

    if read_only.is_empty() && writable.is_empty() && executable.is_empty() {
        return;
    }
    sbpl!(
        sb,
        ";; User-overridden paths in sensitive directories (allow.read / allow.write / allow.exec)"
    );
    for path in &read_only {
        sbpl!(sb, "(allow file-read* (subpath \"{path}\"))");
    }
    for path in &writable {
        sbpl!(sb, "(allow file-read* (subpath \"{path}\"))");
        sbpl!(sb, "(allow file-write* (subpath \"{path}\"))");
    }
    for path in &executable {
        sbpl!(sb, "(allow file-read* (subpath \"{path}\"))");
        sbpl!(sb, "(allow file-map-executable (subpath \"{path}\"))");
    }
    sbpl!(sb);
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
    proxy_forced: bool,
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
    // Proxy-forced mode (#53): do NOT allow direct egress to `*:443`. Instead
    // the only outbound allowance is `localhost:{proxy_port}`, emitted below with
    // the other localhost carve-outs. Unlike Landlock (port-based), SBPL CAN pin
    // to localhost, so this gives macOS FULL enforcement with no residual: a
    // direct connect to any remote host on :443 is denied and all HTTPS must go
    // through the CONNECT proxy, defeating the `env -u HTTPS_PROXY` bypass.
    //
    // Fail closed: if `proxy_forced` is set but `proxy_port` is None (a
    // contradiction the orchestration already prevents), we emit NO outbound-443
    // rule and NO localhost proxy carve-out — the deny-by-default profile then
    // blocks all remote TCP, which is the safe failure rather than an open one.
    //
    // `extra_ports` (#297) is gated on the same condition, and for the same
    // reason. `(remote ip "*:{port}")` is a direct path to ANY remote host on
    // that port, family-agnostic so it carries UDP too — a channel the proxy
    // never sees, that `allowed_domains`/`blocked_domains` never filter, and
    // that no cooperating localhost process is needed to reach. Leaving it
    // ungated made the "no residual" claim above false for every user who
    // passed `--allow-port`. The port stays in the *proxy's* allowed-port
    // policy, so a proxy-aware tool still reaches `remote:{port}` by CONNECT,
    // logged and domain-filtered; only non-proxy-aware raw TCP loses the path,
    // which is precisely what this mode exists to take away. `main.rs` warns
    // when the two are combined, so the narrowing is never silent.
    if !proxy_forced {
        sbpl!(sb, "(allow network-outbound (remote ip \"*:443\"))");

        // Extra ports (e.g., MCP servers, custom services)
        for port in extra_ports {
            sbpl!(sb, "(allow network-outbound (remote ip \"*:{port}\"))");
        }
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

// ── Tests (cross-platform: SBPL text generation only) ──────────
//
// These assert the generated profile *string* contains the right rules. They
// do NOT prove the macOS kernel enforces them — that is verified at runtime by
// the `integration` suite, which can only run on macOS/CI.

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal `SandboxConfig` for SBPL-string tests.
    /// Resolving git from trusted directories means `git_common_dir` is `None`
    /// on a machine whose git lives elsewhere. The denies for an ordinary repo
    /// must not depend on it: `<root>/.git` is seeded for every writable root
    /// unconditionally, so the hooks and config denies stand with no git at all.
    ///
    /// Pins the boundary of that guarantee — a worktree's *shared* gitdir, and
    /// any grant whose repo data is not at `<root>/.git`, still need resolving.
    /// `discover::gitdir_without_git` recovers those by reading the `.git`
    /// pointer (and its `commondir`) without spawning anything.
    #[test]
    fn git_persistence_denies_do_not_depend_on_a_resolved_git() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        opts.git_common_dir = None;
        let p = generate_profile(&opts, &[]);
        for rule in [
            r#"(deny file-write* (subpath "/projects/app/.git/hooks"))"#,
            r#"(deny file-write* (literal "/projects/app/.git/config"))"#,
        ] {
            assert!(p.contains(rule), "MISSING without git_common_dir: {rule}");
        }
    }

    /// Finding B: `allow.exec` inside a credential directory was emitted by
    /// `emit_user_allows`, i.e. *before* `emit_deny_rules` re-denies `file-read*`
    /// on the dotfile subpath, and nothing re-allowed it afterwards. So
    /// `allow.exec = ["~/.docker/cli-plugins"]` — a real layout, as is
    /// `~/.terraform.d/plugins` — worked on Linux, where the grant is simply an
    /// additive Landlock rule, and silently did nothing on macOS.
    #[test]
    fn profile_extra_exec_overrides_a_denied_dotfile_directory() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let granted = [PathBuf::from("/Users/test/.docker/cli-plugins")];
        let mut opts = test_options(project, home);
        opts.extra_exec = &granted;
        let p = generate_profile(&opts, &[]);

        let deny = p
            .find("(deny file-read* (subpath \"/Users/test/.docker\"))")
            .expect("the blanket ~/.docker read deny must still be emitted");
        for rule in [
            "(allow file-read* (subpath \"/Users/test/.docker/cli-plugins\"))",
            "(allow file-map-executable (subpath \"/Users/test/.docker/cli-plugins\"))",
        ] {
            let at = p
                .rfind(rule)
                .unwrap_or_else(|| panic!("missing post-deny re-allow: {rule}\n{p}"));
            assert!(
                at > deny,
                "re-allow must come AFTER the subpath deny (SBPL last-match-wins): {rule}"
            );
        }
        // The exec tree still stays read-only.
        assert!(
            p.rfind("(deny file-write* (subpath \"/Users/test/.docker/cli-plugins\"))")
                .is_some_and(|at| at > deny),
            "the write-deny on the exec tree must survive the re-allow:\n{p}"
        );
    }

    /// Finding C: the re-allow used `(literal ...)`, which matches the directory
    /// entry and nothing beneath it, so a grant on a subdirectory of a credential
    /// dir — `~/.aws/sso/cache`, `~/.kube/cache` — granted the whole subtree on
    /// Linux (`path_beneath`) and effectively nothing on macOS. `subpath` makes the
    /// two backends mean the same thing.
    #[test]
    fn profile_extra_read_on_a_subdir_of_a_denied_dotfile_dir_is_a_subtree() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let granted = [PathBuf::from("/Users/test/.aws/sso/cache")];
        let mut opts = test_options(project, home);
        opts.extra_read = &granted;
        let p = generate_profile(&opts, &[]);

        let deny = p
            .find("(deny file-read* (subpath \"/Users/test/.aws\"))")
            .expect("the blanket ~/.aws read deny must still be emitted");
        let allow = p
            .rfind("(allow file-read* (subpath \"/Users/test/.aws/sso/cache\"))")
            .expect("the re-allow must name the subtree, not just the directory entry");
        assert!(allow > deny, "re-allow must come AFTER the subpath deny");
        assert!(
            !p.contains("(allow file-read* (literal \"/Users/test/.aws/sso/cache\"))"),
            "a literal re-allow matches the directory entry only, which is the silent half of #312:\n{p}"
        );
        // Nothing else in ~/.aws is reopened.
        assert!(
            !p.contains("/Users/test/.aws/credentials"),
            "the grant must not reach beyond the path it names:\n{p}"
        );
    }

    /// `allow.write` on a file inside a `DENIED_DOTFILES` directory must reach
    /// the profile as a post-deny re-allow, exactly as `allow.read` does.
    ///
    /// The concrete case: stock `ssh` appends to `~/.ssh/known_hosts` on a first
    /// connection under the default `StrictHostKeyChecking`. Before this, the
    /// write grant was emitted by `emit_user_allows` — i.e. *before*
    /// `emit_deny_rules` — lost to the subpath deny, and did nothing at all on
    /// macOS while working on Linux. Verified against the live sandbox with
    /// `cplt check path --write`, which reported the model/probe mismatch.
    ///
    /// Read comes with write deliberately: a grant that can write a file it
    /// cannot read is not a usable grant, and `emit_user_allows` pairs them the
    /// same way.
    #[test]
    fn profile_extra_write_overrides_a_denied_dotfile_file() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let granted = [PathBuf::from("/Users/test/.ssh/known_hosts")];
        let mut opts = test_options(project, home);
        opts.extra_write = &granted;
        let p = generate_profile(&opts, &[]);

        let deny = p
            .find(r#"(deny file-write* (subpath "/Users/test/.ssh"))"#)
            .expect("the blanket ~/.ssh write deny must still be emitted");
        for rule in [
            r#"(allow file-read* (subpath "/Users/test/.ssh/known_hosts"))"#,
            r#"(allow file-write* (subpath "/Users/test/.ssh/known_hosts"))"#,
        ] {
            // rfind: `emit_user_allows` emits the same read rule earlier for a
            // write grant, and the one that has to outrank the deny is the last.
            let at = p
                .rfind(rule)
                .unwrap_or_else(|| panic!("missing post-deny re-allow: {rule}"));
            assert!(
                at > deny,
                "re-allow must come AFTER the subpath deny (SBPL last-match-wins): {rule}"
            );
        }
        // Scoped to the granted file: a sibling key stays denied.
        assert!(
            !p.contains(r#"(subpath "/Users/test/.ssh/id_ed25519")"#),
            "a write grant must not reopen anything but the file it names:\n{p}"
        );
    }

    /// A grant naming the directory itself is not an override. `sandbox::prepare`
    /// refuses such a run outright (#291), and this is the second line: even if
    /// one reached `generate_profile`, it must not turn into a subpath re-allow
    /// that reopens every key in `~/.ssh`.
    #[test]
    fn profile_never_reopens_a_denied_dotfile_directory_itself() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let granted = [PathBuf::from("/Users/test/.ssh")];
        for (read, write) in [(true, false), (false, true)] {
            let mut opts = test_options(project, home);
            if read {
                opts.extra_read = &granted;
            }
            if write {
                opts.extra_write = &granted;
            }
            let p = generate_profile(&opts, &[]);
            let deny = p
                .find(r#"(deny file-read* (subpath "/Users/test/.ssh"))"#)
                .expect("the blanket ~/.ssh deny must still be emitted");
            assert!(
                !p[deny..].contains(r#"(literal "/Users/test/.ssh")"#),
                "a directory grant must produce no post-deny re-allow:\n{p}"
            );
        }
    }

    fn test_options<'a>(
        project_dir: &'a std::path::Path,
        home_dir: &'a std::path::Path,
    ) -> SandboxConfig<'a> {
        SandboxConfig {
            project_dir,
            home_dir,
            extra_read: &[],
            extra_write: &[],
            extra_exec: &[],
            extra_socket: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            playwright_socket_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            java_home: None,
            dotnet_root: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            allow_msbuild: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: crate::agent::Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
            keychain_substitute: None,
            use_bubblewrap: None,
        }
    }

    #[test]
    fn relative_repo_deny_path_is_emitted_absolute() {
        // Issue #179, macOS half: a relative `.cplt.toml` deny path used to be
        // interpolated verbatim as `(deny file-read* (subpath "secrets"))`.
        // Seatbelt accepts that without a compile error and the rule matches
        // nothing — a silent fail-open. apply_repo_config now anchors it.
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");

        let mut resolved = crate::config::Config::default()
            .merge(crate::config::CliFlags::default())
            .expect("merge");
        let repo_config = crate::repo_config::RepoConfig {
            deny: crate::repo_config::DenySection {
                paths: vec!["secrets".to_string()],
                env: vec![],
            },
            ..Default::default()
        };
        resolved.apply_repo_config(&repo_config, project, &[]);

        let mut opts = test_options(project, home);
        opts.extra_deny = &resolved.deny_paths;
        let p = generate_profile(&opts, &[]);

        assert!(
            p.contains(r#"(deny file-read* (subpath "/projects/app/secrets"))"#),
            "repo deny path must reach SBPL as an absolute subpath"
        );
        assert!(
            !p.contains(r#"(subpath "secrets")"#),
            "a bare relative subpath compiles but never matches — fail-open"
        );
    }

    #[test]
    fn default_path_allows_wildcard_443() {
        // Regression guard: with proxy_forced=false the broad `*:443` allowance
        // must remain exactly as before #53.
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let opts = test_options(project, home);
        assert!(!opts.proxy_forced);
        let p = generate_profile(&opts, &[]);

        assert!(p.contains("(allow network-outbound (remote ip \"*:443\"))"));
    }

    #[test]
    fn proxy_forced_replaces_443_with_localhost_proxy() {
        // #53: with proxy_forced=true the broad `*:443` rule is dropped and the
        // only outbound allowance is `localhost:{proxy_port}` — SBPL can pin to
        // localhost, so macOS gets full enforcement with no residual.
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        opts.proxy_forced = true;
        opts.proxy_port = Some(8080);
        let p = generate_profile(&opts, &[]);

        assert!(
            p.contains("(allow network-outbound (remote ip \"localhost:8080\"))"),
            "proxy_forced must pin outbound to the localhost proxy port"
        );
        assert!(
            !p.contains("\"*:443\""),
            "proxy_forced must drop the broad *:443 allowance"
        );
    }

    #[test]
    fn extra_ports_are_direct_egress_in_default_mode_only() {
        // #297: `--allow-port 9999` emits `(remote ip "*:9999")`, a direct path
        // to any remote host on that port. Under proxy_forced that path must be
        // gone, or the "no residual" claim on the rule above is false. The same
        // options run both ways, so the assertion can only pass by the gate.
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let ports = [9999u16];

        let mut opts = test_options(project, home);
        opts.extra_ports = &ports;
        let default_mode = generate_profile(&opts, &[]);
        assert!(
            default_mode.contains("(allow network-outbound (remote ip \"*:9999\"))"),
            "default mode must still honour --allow-port"
        );

        opts.proxy_forced = true;
        opts.proxy_port = Some(8080);
        let forced = generate_profile(&opts, &[]);
        assert!(
            !forced.contains("*:9999"),
            "proxy_forced must not emit a direct remote path for an extra port"
        );
        assert!(
            forced.contains("(allow network-outbound (remote ip \"localhost:8080\"))"),
            "proxy_forced still pins egress to the localhost proxy port"
        );
    }

    /// #126 Tier 1b: SBPL uses last-match-wins, so every security `(deny ...)`
    /// MUST be emitted AFTER the broader `(allow ...)` it overrides. Nothing
    /// asserted this ordering, so reordering a deny before its allow (silently
    /// permitting `.git/config` writes or credential reads) left every other test
    /// green. This pins the byte-offset ordering for the sensitive rules.
    #[test]
    fn sensitive_denies_come_after_their_broader_allows() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let p = generate_profile(&test_options(project, home), &[]);

        // Helper: assert `allow` appears strictly before `deny` in the profile.
        let assert_deny_after_allow = |allow: &str, deny: &str| {
            let a = p
                .find(allow)
                .unwrap_or_else(|| panic!("expected allow rule missing from profile: {allow}"));
            let d = p
                .find(deny)
                .unwrap_or_else(|| panic!("expected deny rule missing from profile: {deny}"));
            assert!(
                a < d,
                "SBPL last-match-wins violated: deny must come AFTER its allow.\n  \
                 allow @ {a}: {allow}\n  deny  @ {d}: {deny}"
            );
        };

        // Project-dir write allow must precede the .git write denies it overrides.
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/projects/app"))"#,
            r#"(deny file-write* (subpath "/projects/app/.git/hooks"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/projects/app"))"#,
            r#"(deny file-write* (literal "/projects/app/.git/config"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/projects/app"))"#,
            r#"(deny file-write* (literal "/projects/app/.cplt.toml"))"#,
        );

        // The broad ~/.m2 tool-dir read allow must precede the credential-file deny
        // (`.m2/settings.xml` lives inside the allowed dir — DENIED_HOME_SUBPATHS).
        assert_deny_after_allow(
            r#"(allow file-read* (subpath "/Users/test/.m2"))"#,
            r#"(deny file-read* (literal "/Users/test/.m2/settings.xml"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-read* (subpath "/Users/test/.gradle"))"#,
            r#"(deny file-read* (literal "/Users/test/.gradle/gradle.properties"))"#,
        );

        // The worktree block is only emitted when there IS a common dir, and
        // `test_options` has none — so re-generate with one. Without this the
        // two orderings below are never exercised at all.
        let common = std::path::Path::new("/Users/test/main/.git");
        let mut opts = test_options(project, home);
        opts.git_common_dir = Some(common);
        // A user allow broad enough to cover the main repo: the worktree denies
        // used to sit next to the worktree allow, where this would reopen them.
        let extra_write = [std::path::PathBuf::from("/Users/test")];
        opts.extra_write = &extra_write;
        let p = generate_profile(&opts, &[]);

        let assert_deny_after_allow = |allow: &str, deny: &str| {
            let a = p
                .find(allow)
                .unwrap_or_else(|| panic!("expected allow rule missing from profile: {allow}"));
            let d = p
                .find(deny)
                .unwrap_or_else(|| panic!("expected deny rule missing from profile: {deny}"));
            assert!(
                a < d,
                "SBPL last-match-wins violated: deny must come AFTER its allow.\n  \
                 allow @ {a}: {allow}\n  deny  @ {d}: {deny}"
            );
        };

        // The worktree grant hands out read+write on the main repo's .git, which
        // can sit anywhere under $HOME — including inside a DENIED_DOTFILES
        // directory. Those denies beat it only because `emit_deny_rules` runs
        // after `emit_git_worktree`, which nothing asserted before now.
        assert_deny_after_allow(
            r#"(allow file-read* (subpath "/Users/test/main/.git"))"#,
            r#"(deny file-read* (subpath "/Users/test/.ssh"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/Users/test/main/.git"))"#,
            r#"(deny file-write* (subpath "/Users/test/.ssh"))"#,
        );

        // And the worktree's own persistence denies must outlast every allow,
        // the user's included — which is why they are emitted at the end of the
        // profile rather than beside the grant they qualify.
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/Users/test"))"#,
            r#"(deny file-write* (subpath "/Users/test/main/.git/hooks"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/Users/test"))"#,
            r#"(deny file-write* (literal "/Users/test/main/.git/config"))"#,
        );
        assert_deny_after_allow(
            r#"(allow file-write* (subpath "/Users/test"))"#,
            r#"(deny file-write-unlink (literal "/Users/test/main/.git"))"#,
        );
    }

    /// #191: Gradle auto-provisions toolchain JDKs into `~/.gradle/jdks`, which
    /// sits inside the `(deny process-exec (subpath "~/.gradle"))` that
    /// `emit_tool_dirs` emits for dependency stores — `java`/`javac` from a
    /// toolchain JDK got EPERM. The carve-out only works if it is emitted AFTER
    /// that deny (last-match-wins), and the paired write-deny only closes the
    /// write-then-exec hole if it is emitted after every write allow, including
    /// a user `allow.write`. Byte offsets, not `contains`, because ordering is
    /// the whole point.
    #[test]
    fn gradle_toolchain_exec_allow_comes_after_the_gradle_exec_deny() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        // Worst case for the write-deny: the user has opened up all of ~/.gradle.
        let extra_write = [std::path::PathBuf::from("/Users/test/.gradle")];
        opts.extra_write = &extra_write;
        let p = generate_profile(&opts, &[]);

        let at = |rule: &str| {
            p.find(rule)
                .unwrap_or_else(|| panic!("rule missing from profile: {rule}"))
        };

        let exec_deny = at(r#"(deny process-exec (subpath "/Users/test/.gradle"))"#);
        let exec_allow = at(r#"(allow process-exec (subpath "/Users/test/.gradle/jdks"))"#);
        assert!(
            exec_deny < exec_allow,
            "toolchain exec allow @ {exec_allow} must come AFTER the .gradle exec deny @ {exec_deny}"
        );

        let write_allow = at(r#"(allow file-write* (subpath "/Users/test/.gradle"))"#);
        let user_write_allow = p
            .rfind(r#"(allow file-write* (subpath "/Users/test/.gradle"))"#)
            .expect("user allow.write rule missing");
        let write_deny = at(r#"(deny file-write* (subpath "/Users/test/.gradle/jdks"))"#);
        assert!(
            write_allow < write_deny && user_write_allow < write_deny,
            "toolchain write deny @ {write_deny} must come AFTER every .gradle write allow \
             (tool dir @ {write_allow}, user allow.write @ {user_write_allow})"
        );

        // Stronger than the two known allows above: nothing emitted later may
        // re-grant write over the exec-allowed subtree. Guards against a future
        // emit_* being appended after emit_gradle_toolchain_write_deny.
        let last_write_allow = p
            .rfind("(allow file-write*")
            .expect("profile has no write allows at all");
        assert!(
            last_write_allow < write_deny,
            "the toolchain write deny @ {write_deny} must be the LAST rule \
             touching write on this subtree; a later (allow file-write*) @ \
             {last_write_allow} would reopen write-then-exec"
        );
    }

    #[test]
    fn proxy_forced_without_port_fails_closed_no_443() {
        // Defensive fail-closed: proxy_forced with no proxy port is a
        // contradiction the orchestration prevents, but the profile must still
        // omit `*:443` (deny remote TCP) rather than re-emit the broad allow.
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        opts.proxy_forced = true;
        opts.proxy_port = None;
        let p = generate_profile(&opts, &[]);

        assert!(
            !p.contains("\"*:443\""),
            "fail-closed: proxy_forced without a port must not emit *:443"
        );
    }

    /// Issue #247: a repo nested under a writable root got no git-persistence
    /// denies at all, so `~/code/other-repo/.git/hooks/post-checkout` was
    /// writable and ran unsandboxed on the user's next git operation there.
    ///
    /// The kernel behaviour behind these strings was verified with
    /// `sandbox-exec` against a real nested repository: the hook plant, the
    /// `.git/config` append, the `mv .git .gitbak` rename and the pointer-file
    /// rewrite are all refused, while `git add`/`commit`/`checkout -b`/`stash`/
    /// `gc` inside that repo — and every write under `src/`, `target/`,
    /// `.github/` — still succeed.
    #[test]
    fn nested_repos_under_every_writable_root_get_git_denies() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        let extra_write = [std::path::PathBuf::from("/Users/test/code")];
        opts.extra_write = &extra_write;
        let p = generate_profile(&opts, &[]);

        for root in ["/projects/app", "/Users/test/code"] {
            let esc = root.replace('.', r"\.");
            for rule in [
                format!(
                    "(deny file-write* (regex #\"^{esc}/.+/\\.git/(hooks|config|commondir|modules)($|/)\"))"
                ),
                format!("(deny file-write-unlink (regex #\"^{esc}/.+/\\.git$\"))"),
                format!("(deny file-write-data (regex #\"^{esc}/.+/\\.git$\"))"),
            ] {
                assert!(p.contains(&rule), "missing for {root}: {rule}\n{p}");
            }
        }

        // Last-match-wins: nothing may re-open write after these.
        let nested_deny = p
            .rfind("/.+/\\.git/(hooks|config|commondir|modules)")
            .expect("nested deny missing");
        let last_write_allow = p.rfind("(allow file-write*").expect("no write allows");
        assert!(
            last_write_allow < nested_deny,
            "a write allow @ {last_write_allow} comes after the nested git deny @ {nested_deny}"
        );
    }

    /// #267: goose auto-spawns MCP servers from `.agents/plugins/`, so a
    /// manifest the agent writes runs on the HOST next session. Denied for
    /// every writable root, not just the project: a granted sibling repo is as
    /// exposed, and the payload fires whichever agent opens that repo.
    #[test]
    fn agents_plugins_is_denied_for_every_writable_root() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        let extra_write = [std::path::PathBuf::from("/Users/test/code")];
        opts.extra_write = &extra_write;
        let p = generate_profile(&opts, &[]);

        for root in ["/projects/app", "/Users/test/code"] {
            let rule = format!("(deny file-write* (subpath \"{root}/.agents/plugins\"))");
            assert!(p.contains(&rule), "missing for {root}: {rule}");
        }

        // Last-match-wins: the deny has to outlive every user allow.write, or a
        // grant on the project reopens the whole thing.
        let deny = p
            .rfind("/.agents/plugins\"))")
            .expect("plugins deny must be emitted");
        let last_allow = p
            .rfind("(allow file-write*")
            .expect("a write allow must be emitted");
        assert!(
            last_allow < deny,
            "a write allow at {last_allow} comes after the plugins deny at {deny}"
        );
    }

    /// A repo nested under a writable root has the same exposure: the manifest
    /// fires whichever agent next opens THAT repo, not the granted one. Same
    /// gap #247 found for `.git/hooks`, and the same regex shape closes it.
    #[test]
    fn agents_plugins_is_denied_in_nested_repos_too() {
        let project = std::path::Path::new("/projects/app");
        let home = std::path::Path::new("/Users/test");
        let mut opts = test_options(project, home);
        let extra_write = [std::path::PathBuf::from("/Users/test/code")];
        opts.extra_write = &extra_write;
        let p = generate_profile(&opts, &[]);

        for root in ["/projects/app", "/Users/test/code"] {
            let esc = root.replace('.', r"\.");
            let rule = format!("(deny file-write* (regex #\"^{esc}/.+/\\.agents/plugins($|/)\"))");
            assert!(p.contains(&rule), "missing nested deny for {root}: {rule}");
        }
    }

    /// The rest of `.agents/` is ordinary state with no auto-execution. Denying
    /// it wholesale would break writes nothing asked to break.
    #[test]
    fn agents_dir_itself_is_not_denied() {
        let p = generate_profile(
            &test_options(
                std::path::Path::new("/projects/app"),
                std::path::Path::new("/Users/test"),
            ),
            &[],
        );
        assert!(
            !p.contains("(deny file-write* (subpath \"/projects/app/.agents\"))"),
            "only .agents/plugins is denied, not the whole tree"
        );
    }

    /// A path is interpolated into a regex, so its metacharacters must not be.
    /// `~/code/v1.0+rc` would otherwise match `v1X0rc`, `v1X00rc`, and more.
    #[test]
    fn nested_gitdir_regex_escapes_path_metacharacters() {
        let project = std::path::Path::new("/projects/v1.0+rc[x]");
        let home = std::path::Path::new("/Users/test");
        let p = generate_profile(&test_options(project, home), &[]);

        assert!(
            p.contains(
                r#"(deny file-write-unlink (regex #"^/projects/v1\.0\+rc\[x\]/.+/\.git$"))"#
            ),
            "path metacharacters not escaped:\n{p}"
        );
    }

    /// Issue #244: `allow.read` entries are canonicalized, so a dotfile-managed
    /// `~/.npmrc` symlink used to miss the `home.join(file)` comparison and the
    /// re-allow was silently never emitted.
    #[test]
    fn symlinked_credential_file_still_gets_its_reallow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        std::fs::create_dir_all(home.join("dotfiles")).expect("mkdir");
        std::fs::write(home.join("dotfiles/npmrc"), "//r/:_authToken=x\n").expect("write");
        std::os::unix::fs::symlink(home.join("dotfiles/npmrc"), home.join(".npmrc"))
            .expect("symlink");

        let project = home.join("proj");
        std::fs::create_dir_all(&project).expect("mkdir");
        let mut opts = test_options(&project, &home);
        // What canonicalize_paths / resolve_config_path would put in extra_read.
        let extra_read = [std::fs::canonicalize(home.join(".npmrc")).expect("canonicalize")];
        assert_eq!(extra_read[0], home.join("dotfiles/npmrc"));
        opts.extra_read = &extra_read;
        let p = generate_profile(&opts, &[]);

        let home_str = home.display();
        assert!(
            p.contains(&format!(
                "(allow file-read* (literal \"{home_str}/.npmrc\"))"
            )),
            "re-allow for the symlinked ~/.npmrc missing from profile:\n{p}"
        );
    }

    /// Same class, `DENIED_DOTFILES` half: a symlinked `~/.aws` must still get
    /// the targeted re-allow, and it must name the `$HOME` path the deny uses.
    #[test]
    fn symlinked_denied_dotfile_dir_still_gets_its_reallow() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = std::fs::canonicalize(tmp.path()).expect("canonicalize");
        std::fs::create_dir_all(home.join("dotfiles/aws")).expect("mkdir");
        std::fs::write(home.join("dotfiles/aws/config"), "[default]\n").expect("write");
        std::os::unix::fs::symlink(home.join("dotfiles/aws"), home.join(".aws")).expect("symlink");

        let project = home.join("proj");
        std::fs::create_dir_all(&project).expect("mkdir");
        let mut opts = test_options(&project, &home);
        let extra_read = [std::fs::canonicalize(home.join(".aws/config")).expect("canonicalize")];
        opts.extra_read = &extra_read;
        let p = generate_profile(&opts, &[]);

        let home_str = home.display();
        assert!(
            p.contains(&format!(
                "(allow file-read* (subpath \"{home_str}/.aws/config\"))"
            )),
            "re-allow naming the $HOME path missing from profile:\n{p}"
        );
    }
}
