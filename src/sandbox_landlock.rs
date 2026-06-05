//! Landlock LSM sandbox backend for Linux.
//!
//! # Cross-platform design
//!
//! This module is **always compiled** on all platforms. The rule generation
//! and description logic is pure Rust with no kernel dependencies, enabling
//! unit tests to run on macOS. Only the kernel application functions are
//! behind `#[cfg(target_os = "linux")]`.
//!
//! # Security model differences from macOS (Seatbelt)
//!
//! Landlock is allowlist-only — it cannot deny access to subpaths within an
//! allowed directory. On macOS, SBPL can deny `.env` reads and `.git/hooks`
//! writes inside the project dir at the kernel level. On Linux, these
//! protections come from the proxy layer (exfiltration blocking) and
//! environment hardening (GIT_CONFIG overrides), not from filesystem rules.
//!
//! Landlock network rules (ABI v4+) are port-based, not address-based.
//! This means port 443 allows connecting to ANY host on that port, including
//! localhost. On macOS, Seatbelt can deny localhost separately, but Landlock
//! cannot. Use `--with-proxy` on Linux for localhost SSRF protection.
//! The proxy handles domain-level filtering on both platforms.

use super::policy::{self, HomeToolDir};
#[cfg(target_os = "linux")]
use crate::ui;
use std::fmt::Write as _;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use landlock::{ABI, PathBeneath};
#[cfg(target_os = "linux")]
use std::os::fd::{BorrowedFd, RawFd};

// ── Cross-platform types ───────────────────────────────────────

/// Filesystem access flags for a Landlock rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsAccess {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    /// Grant `LANDLOCK_ACCESS_FS_IOCTL_DEV` (Landlock ABI v5+, kernel ≥ 6.8).
    ///
    /// Required for character and block devices that need `ioctl()` — most
    /// importantly `/dev/tty` and `/dev/pts/*` for `tcsetattr()` (raw mode).
    /// Without this flag on ABI v5+, the terminal stays in cooked/echo mode:
    /// OSC colour-query responses are echoed as visible text and the process
    /// hangs waiting for a response it already "missed".
    ///
    /// For non-device files and directories `IoctlDev` is a no-op; set it
    /// only on device paths to keep the policy least-privilege.
    pub ioctl: bool,
}

/// A filesystem access rule: allow `access` on `path` and its subtree.
///
/// Landlock is deny-by-default — only paths with explicit rules are
/// accessible. Sensitive paths (`.ssh`, `.gnupg`, etc.) are simply
/// not added to the ruleset.
#[derive(Debug, Clone)]
pub struct FsRule {
    pub path: PathBuf,
    pub access: FsAccess,
}

/// TCP connect rule (requires Landlock ABI v4+, kernel 6.7+).
#[derive(Debug, Clone, Copy)]
pub struct NetRule {
    pub port: u16,
}

/// Complete Landlock policy compiled from SandboxConfig.
///
/// This is a platform-agnostic description of what the Landlock ruleset
/// will enforce. It's built by [`generate_policy()`] and applied by
/// [`apply_policy()`] (Linux only).
#[derive(Debug, Clone)]
pub struct LandlockPolicy {
    pub fs_rules: Vec<FsRule>,
    pub net_rules: Vec<NetRule>,
    /// Whether to handle (and thus restrict) TCP connect at the kernel level.
    /// When false, all outbound TCP connect is unrestricted by Landlock.
    /// This is set to false when `allow_localhost_any` is true because Landlock
    /// network rules are port-based only — they cannot distinguish localhost
    /// from remote hosts. The proxy still provides domain-level filtering.
    pub restrict_net_connect: bool,
    /// Home directory — used to pre-create writable cache directories that
    /// Landlock needs to open(O_PATH) before the sandbox is applied.
    pub home_dir: PathBuf,
}

/// Pre-computed data for sandbox application in the child process.
///
/// Everything here is computed in the parent (where allocation and I/O
/// are safe). The `pre_exec` hook only receives this immutable data and
/// makes raw syscalls — no allocation, no file I/O, with one exception:
/// paths in `deferred_paths` are magic symlinks (e.g. `/proc/self`) that
/// must be opened in the child after fork so they resolve to the child's
/// pid rather than the parent's.
///
/// File descriptors in `pre_opened_fds` are opened with `O_PATH | O_CLOEXEC`
/// in `precompute()`. They survive `fork()` and are used by
/// `apply_precomputed()` via `BorrowedFd` — no `open()` or allocation
/// in the async-signal-unsafe post-fork context, except for the deferred
/// paths described above.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct PrecomputedSandbox {
    pub abi_version: ABI,
    /// Pre-opened `O_PATH` file descriptors for Landlock filesystem rules.
    /// Opened in `precompute()` (parent), used in `apply_precomputed()` (child).
    /// Raw fds (i32) so the struct remains Clone-able. Closed on exec via
    /// `O_CLOEXEC`; the parent leaks them (harmless — ~30 fds, program exits).
    pub pre_opened_fds: Vec<(RawFd, FsAccess)>,
    /// Paths that must be opened in the child process because they are magic
    /// symlinks that resolve differently per-process (e.g. `/proc/self` resolves
    /// to `/proc/<pid>` — the parent's pid, not the child's).
    /// `CString` allocation happens in `precompute()` (parent, safe).
    /// The actual `open()` call happens in `apply_precomputed()` (child).
    pub deferred_paths: Vec<(std::ffi::CString, FsAccess)>,
    pub net_rules: Vec<NetRule>,
    /// Whether to restrict TCP connect at the kernel level.
    pub restrict_net_connect: bool,
    pub seccomp_filter: Vec<BpfInstruction>,
}

/// A single BPF instruction for the seccomp filter.
///
/// Pre-built in the parent, applied via prctl in the child.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

// ── Linux-specific constants ───────────────────────────────────
//
// These mirror the macOS constants in sandbox_policy.rs but with
// Linux-specific paths. Some duplication with macOS is intentional
// to keep each platform's paths independent and auditable.

/// System paths that need read access.
/// Linux equivalent of macOS `SYSTEM_READ_FILES` in sandbox_policy.rs.
const LINUX_SYSTEM_READ_PATHS: &[&str] = &[
    "/etc/ssl",
    "/etc/pki",             // RHEL/Fedora CA certificates
    "/etc/ca-certificates", // Debian/Ubuntu CA certificates
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf", // Name service switch (DNS resolution)
    "/etc/host.conf",     // Resolver configuration
    "/etc/gai.conf",      // getaddrinfo configuration
    "/etc/shells",
    "/etc/passwd",
    "/etc/localtime",
    "/etc/ld.so.cache",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/zshrc",
    "/etc/bashrc",
    "/etc/bash.bashrc", // Debian/Ubuntu
    "/etc/profile",
    "/etc/profile.d",
    "/etc/alternatives", // Debian alternatives system
    "/etc/environment",
    "/etc/default",
    "/etc/security", // PAM config (read-only)
    "/usr/include",  // C/C++ system headers — needed by cc/gcc for native crate builds
];

/// Tool directories with read + execute access.
/// Linux equivalent of macOS `TOOL_READ_DIRS` in sandbox_policy.rs.
const LINUX_TOOL_DIRS: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local",
    "/usr/share",
    "/lib",
    "/lib64",
    "/snap",               // Ubuntu Snap packages
    "/run/current-system", // NixOS
];

/// Individual home config files (and select config directories) that tools
/// need read access to.
///
/// File entries grant access to a single file. Directory entries (e.g.
/// `.config/mise`) grant recursive read access to the subtree — this is
/// acceptable because these directories contain only tool configuration,
/// not secrets.
///
/// Mirrors the macOS SBPL literal file allows in `emit_system_access()`.
const LINUX_HOME_CONFIG_FILES: &[&str] = &[
    // Git configuration (includes user-config, attributes, ignore, etc.)
    ".gitconfig",
    ".config/git",
    // GitHub CLI auth (specific files only)
    ".config/gh/hosts.yml",
    ".config/gh/config.yml",
    // Tool version managers
    ".tool-versions",
    // mise config directory (tool versions, env settings — no secrets)
    ".config/mise",
    // Shell startup (tools source these for PATH)
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    ".zprofile",
    // Node.js REPL history
    ".node_repl_history",
];

/// Device and pseudo-filesystem paths that Node.js and common tools need.
const DEVICE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/dev/random",
    "/dev/tty",  // Terminal device (interactive tools)
    "/dev/ptmx", // PTY master multiplexer — required by forkpty(3)
    "/dev/pts",  // Pseudo-terminal slave devices
    "/dev/shm",  // POSIX shared memory (Node.js, Chromium)
];

// ── Policy generation (cross-platform, pure logic) ─────────────

/// Generate a Landlock policy from a sandbox configuration.
///
/// This is pure logic with no kernel calls — it translates the
/// platform-agnostic `SandboxConfig` into a set of `FsRule` and
/// `NetRule` values that describe what the sandbox should allow.
///
/// Returns a `LandlockPolicy` that can be applied with `apply_policy()`
/// on Linux, or described with `describe_policy()` on any platform.
pub fn generate_policy(config: &super::SandboxConfig) -> LandlockPolicy {
    let mut fs_rules = Vec::new();
    let home = config.home_dir;

    // ── Project directory: full access ──
    fs_rules.push(FsRule {
        path: config.project_dir.to_path_buf(),
        access: FsAccess {
            read: true,
            write: true,
            execute: true,
            ioctl: false,
        },
    });

    // ── System read paths ──
    for &p in LINUX_SYSTEM_READ_PATHS {
        fs_rules.push(FsRule {
            path: PathBuf::from(p),
            access: FsAccess {
                read: true,
                write: false,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── Tool directories: read + execute ──
    for &p in LINUX_TOOL_DIRS {
        fs_rules.push(FsRule {
            path: PathBuf::from(p),
            access: FsAccess {
                read: true,
                write: false,
                execute: true,
                ioctl: false,
            },
        });
    }

    // ── Application directories (filtered by discovery) ──
    for dir in policy::app_dirs() {
        let process_exec = dir.process_exec_paths(home);
        let map_exec = dir.map_exec_paths(home);
        let write = dir.write_paths(home);
        let read = dir.read_paths(home);
        // all_paths() returns deduplicated union of all categories
        for path in dir.all_paths(home) {
            let include = match &config.existing_app_dirs {
                Some(existing) => existing
                    .iter()
                    .any(|e| e == path.to_string_lossy().as_ref()),
                None => true,
            };
            if include {
                let execute = process_exec.contains(&path) || map_exec.contains(&path);
                let writable = write.contains(&path);
                // read permission mirrors SBPL: only paths in read_paths() get file-read*.
                // A write-only path (not in read_paths) does not get read access.
                let readable = read.contains(&path);
                fs_rules.push(FsRule {
                    path,
                    access: FsAccess {
                        read: readable,
                        write: writable,
                        execute,
                        ioctl: false,
                    },
                });
            }
        }
    }

    // ── Home tool directories (filtered by discovery) ──
    for dir in policy::home_tool_dirs() {
        if should_include_tool_dir(dir, config) {
            fs_rules.push(FsRule {
                path: home.join(dir.path),
                access: FsAccess {
                    read: true,
                    write: dir.write,
                    execute: dir.process_exec || dir.map_exec,
                    ioctl: false,
                },
            });
        }
    }

    // ── Copilot install directory: read + execute ──
    if let Some(dir) = config.copilot_install_dir {
        fs_rules.push(FsRule {
            path: dir.to_path_buf(),
            access: FsAccess {
                read: true,
                write: false,
                execute: true,
                ioctl: false,
            },
        });
    }

    // ── Git hooks path: read + execute ──
    if let Some(p) = config.git_hooks_path {
        fs_rules.push(FsRule {
            path: p.to_path_buf(),
            access: FsAccess {
                read: true,
                write: false,
                execute: true,
                ioctl: false,
            },
        });
    }

    // ── Git worktree common dir: read + write ──
    if let Some(p) = config.git_common_dir {
        fs_rules.push(FsRule {
            path: p.to_path_buf(),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── Scratch directory: read + write + execute (always) ──
    // The scratch dir is the controlled alternative to /tmp for compile-then-exec
    // workflows (e.g. node-gyp, cargo). Execute is always allowed here regardless
    // of allow_tmp_exec, which controls only system temp dirs like /tmp.
    if let Some(dir) = config.scratch_dir {
        fs_rules.push(FsRule {
            path: dir.to_path_buf(),
            access: FsAccess {
                read: true,
                write: true,
                execute: true,
                ioctl: false,
            },
        });
    }

    // ── /tmp: read + write, execute if allow_tmp_exec OR allow_jvm_attach ──
    // ByteBuddy/MockK self-attach spawns a helper process that writes temp files
    // to /tmp and the JVM may dlopen() native libs from there.
    fs_rules.push(FsRule {
        path: PathBuf::from("/tmp"),
        access: FsAccess {
            read: true,
            write: true,
            execute: config.allow_tmp_exec || config.allow_jvm_attach,
            ioctl: false,
        },
    });

    // ── Device files: read + write + ioctl (no execute) ──
    // ioctl: true grants LANDLOCK_ACCESS_FS_IOCTL_DEV (ABI v5+, kernel ≥ 6.8).
    // Without it, tcsetattr() on /dev/tty and /dev/pts/* is denied — the
    // terminal stays in cooked/echo mode and Copilot's TUI hangs.
    for &dev in DEVICE_FILES {
        fs_rules.push(FsRule {
            path: PathBuf::from(dev),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
                ioctl: true,
            },
        });
    }

    // ── /proc/self: Node.js reads /proc/self/exe, /proc/self/maps, /proc/self/cgroup ──
    // This path is a magic symlink resolved per-process. It is deferred to the
    // child in apply_precomputed() where it resolves to the correct pid.
    fs_rules.push(FsRule {
        path: PathBuf::from("/proc/self"),
        access: FsAccess {
            read: true,
            write: false,
            execute: false,
            ioctl: false,
        },
    });

    // ── /proc: JVM Attach API needs to read /proc/<pid>/ of the target JVM ──
    // ByteBuddy/MockK self-attach spawns an external process that reads
    // /proc/<target_pid>/cmdline, /proc/<target_pid>/root/tmp/, etc.
    // Only granted with allow_jvm_attach since /proc can expose process info.
    if config.allow_jvm_attach {
        fs_rules.push(FsRule {
            path: PathBuf::from("/proc"),
            access: FsAccess {
                read: true,
                write: false,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── Extra read paths from config ──
    for p in config.extra_read {
        fs_rules.push(FsRule {
            path: p.clone(),
            access: FsAccess {
                read: true,
                write: false,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── Extra write paths from config ──
    for p in config.extra_write {
        fs_rules.push(FsRule {
            path: p.clone(),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── GPG signing files (read-only subset of ~/.gnupg) ──
    if config.allow_gpg_signing {
        for &file in policy::GPG_SIGNING_ALLOW_FILES {
            fs_rules.push(FsRule {
                path: home.join(".gnupg").join(file),
                access: FsAccess {
                    read: true,
                    write: false,
                    execute: false,
                    ioctl: false,
                },
            });
        }
        // gpg-agent and keyboxd sockets (read + write for IPC)
        for socket in &["S.gpg-agent", "S.keyboxd"] {
            fs_rules.push(FsRule {
                path: home.join(".gnupg").join(socket),
                access: FsAccess {
                    read: true,
                    write: true,
                    execute: false,
                    ioctl: false,
                },
            });
        }
    }

    // ── Home config files: individual read-only rules ──
    // Landlock PathBeneath rules are always recursive — a rule on $HOME
    // would grant read to the entire home tree including ~/.ssh, ~/.gnupg.
    // Instead, enumerate the specific config files/dirs that tools need.
    for &file in LINUX_HOME_CONFIG_FILES {
        fs_rules.push(FsRule {
            path: home.join(file),
            access: FsAccess {
                read: true,
                write: false,
                execute: false,
                ioctl: false,
            },
        });
    }

    // ── Agent-specific directories ──
    if config.agent.needs_copilot_dir() {
        // Copilot config — auth tokens, settings, native modules.
        // Execute needed for dlopen() of native .node addons (keytar, pty, computer).
        fs_rules.push(FsRule {
            path: home.join(".copilot"),
            access: FsAccess {
                read: true,
                write: true,
                execute: true,
                ioctl: false,
            },
        });
    }
    for dir in config.agent_dirs {
        fs_rules.push(FsRule {
            path: dir.path.clone(),
            access: FsAccess {
                read: true,
                write: dir.write,
                execute: dir.process_exec || dir.map_exec,
                ioctl: false,
            },
        });
        // File-level write grants within a read-only dir
        for file in &dir.write_files {
            fs_rules.push(FsRule {
                path: dir.path.join(file),
                access: FsAccess {
                    read: true,
                    write: true,
                    execute: false,
                    ioctl: false,
                },
            });
        }
    }

    // ── Network rules (requires ABI v4+, kernel 6.7+) ──
    // Always allow HTTPS (443) — Copilot needs it to reach GitHub APIs.
    // This mirrors the macOS SBPL profile which allows outbound 443.
    let mut net_rules = vec![NetRule { port: 443 }];
    if let Some(port) = config.proxy_port
        && !net_rules.iter().any(|r| r.port == port)
    {
        net_rules.push(NetRule { port });
    }
    for &port in config.extra_ports {
        if !net_rules.iter().any(|r| r.port == port) {
            net_rules.push(NetRule { port });
        }
    }
    for &port in config.localhost_ports {
        if !net_rules.iter().any(|r| r.port == port) {
            net_rules.push(NetRule { port });
        }
    }

    // Denied dotfiles and denied files are handled by simply NOT adding
    // them to the ruleset — Landlock is deny-by-default.
    //
    // Note: This means we cannot deny subpaths within an allowed tree
    // (e.g. .env files inside the project dir). Those protections come
    // from the proxy (blocks exfiltration) and env hardening (blocks
    // hook injection). See module-level doc comment.

    // Landlock network rules are port-based only — they cannot distinguish
    // localhost from remote hosts. When allow_localhost_any is true, we must
    // disable kernel-level ConnectTcp restriction entirely (the proxy still
    // provides domain filtering and port enforcement for remote connections).
    let restrict_net_connect = !config.allow_localhost_any;

    LandlockPolicy {
        fs_rules,
        net_rules,
        restrict_net_connect,
        home_dir: home.to_path_buf(),
    }
}

/// Check if a home tool directory should be included based on discovery data.
fn should_include_tool_dir(dir: &HomeToolDir, config: &super::SandboxConfig) -> bool {
    match &config.existing_home_tool_dirs {
        Some(existing) => existing.iter().any(|e| e == dir.path),
        None => true,
    }
}

/// Human-readable summary of the Landlock policy for `--print-profile`.
pub fn describe_policy(policy: &LandlockPolicy) -> String {
    let mut out = String::new();
    out.push_str("# Landlock filesystem policy (deny-by-default)\n");
    out.push_str("# Only listed paths are accessible. Everything else is denied.\n\n");

    let mut full = Vec::new();
    let mut read_exec = Vec::new();
    let mut read_write = Vec::new();
    let mut read_only = Vec::new();
    let mut write_only = Vec::new();

    for rule in &policy.fs_rules {
        let a = &rule.access;
        match (a.read, a.write, a.execute) {
            (true, true, true) => full.push(&rule.path),
            (true, false, true) => read_exec.push(&rule.path),
            (true, true, false) => read_write.push(&rule.path),
            (true, false, false) => read_only.push(&rule.path),
            (false, true, false) => write_only.push(&rule.path),
            _ => {} // other combinations are unusual
        }
    }

    if !full.is_empty() {
        out.push_str("## Full access (read + write + execute)\n");
        for p in &full {
            let _ = writeln!(out, "  {}", p.display());
        }
        out.push('\n');
    }
    if !read_exec.is_empty() {
        out.push_str("## Read + execute\n");
        for p in &read_exec {
            let _ = writeln!(out, "  {}", p.display());
        }
        out.push('\n');
    }
    if !read_write.is_empty() {
        out.push_str("## Read + write\n");
        for p in &read_write {
            let _ = writeln!(out, "  {}", p.display());
        }
        out.push('\n');
    }
    if !read_only.is_empty() {
        out.push_str("## Read only\n");
        for p in &read_only {
            let _ = writeln!(out, "  {}", p.display());
        }
        out.push('\n');
    }
    if !write_only.is_empty() {
        out.push_str("## Write only\n");
        for p in &write_only {
            let _ = writeln!(out, "  {}", p.display());
        }
        out.push('\n');
    }

    if !policy.restrict_net_connect {
        out.push_str("## Network (TCP connect)\n");
        out.push_str("  UNRESTRICTED (--allow-localhost-any; proxy provides filtering)\n\n");
    } else if !policy.net_rules.is_empty() {
        out.push_str("## Network (TCP connect, requires kernel 6.7+ / ABI v4)\n");
        for rule in &policy.net_rules {
            let _ = writeln!(out, "  port {}", rule.port);
        }
        out.push('\n');
    }

    out.push_str("# Note: Landlock is allowlist-only. Paths not listed above are denied.\n");
    out.push_str(
        "# Intra-project deny rules (.env, .pem, .git/hooks) are enforced by\n\
         # environment hardening and proxy filtering, not filesystem rules.\n",
    );

    out
}

// ── Linux-only: Landlock kernel application ────────────────────

/// Check Landlock availability and return the highest supported ABI version.
///
/// Probes the kernel by attempting to create a Ruleset for each ABI level
/// (V6 down to V1) with `HardRequirement` compatibility. Returns the highest
/// ABI that the kernel successfully supports.
///
/// Called in the parent process during `prepare()` — never in `pre_exec`.
#[cfg(target_os = "linux")]
pub fn check_availability() -> Result<ABI, String> {
    const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, ABI::V5, ABI::V4, ABI::V3, ABI::V2, ABI::V1];

    let mut last_error = None;
    for &abi in &ABI_PROBE_ORDER {
        match probe_abi_candidate(abi) {
            Ok(()) => return Ok(abi),
            Err(err) => {
                last_error = Some(format!("ABI {abi:?}: {err}"));
            }
        }
    }

    match last_error {
        None => {
            unreachable!("ABI_PROBE_ORDER is non-empty")
        }
        Some(e) => Err(format!(
            "Landlock is not available on this system: {e}\n\
             Requires Linux 5.13+ with Landlock enabled in the kernel.\n\
             Check: cat /sys/kernel/security/lsm (should include 'landlock')"
        )),
    }
}

#[cfg(target_os = "linux")]
fn probe_abi_candidate(abi: ABI) -> Result<(), String> {
    use landlock::{
        Access, AccessFs, AccessNet, CompatLevel, Compatible, Ruleset, RulesetAttr, Scope,
    };

    let mut ruleset = Ruleset::default().set_compatibility(CompatLevel::HardRequirement);

    ruleset = ruleset
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("filesystem access probe failed: {e}"))?;

    let handled_net = AccessNet::from_all(abi);
    if !handled_net.is_empty() {
        ruleset = ruleset
            .handle_access(handled_net)
            .map_err(|e| format!("network access probe failed: {e}"))?;
    }

    let scopes = Scope::from_all(abi);
    if !scopes.is_empty() {
        ruleset = ruleset
            .scope(scopes)
            .map_err(|e| format!("scope probe failed: {e}"))?;
    }

    ruleset
        .create()
        .map_err(|e| format!("ruleset creation probe failed: {e}"))?;

    Ok(())
}

/// Pre-compute all sandbox data in the parent process.
///
/// This does all I/O and allocation before fork(), so the `pre_exec`
/// hook only needs to make raw syscalls. This avoids async-signal-safety
/// issues when forking a multi-threaded process (the proxy thread may
/// be running).
///
/// File descriptors are opened here with `O_PATH | O_CLOEXEC`. The
/// `CString` allocation for path conversion happens safely in the parent.
/// The child's `pre_exec` hook receives only raw fd numbers.
///
/// Exception: paths that are magic symlinks (e.g. `/proc/self`) cannot
/// be resolved in the parent because they would yield the parent's pid.
/// These are stored in `deferred_paths` and opened with a single `open()`
/// call in the child after fork.
///
/// Platform difference: Landlock operates on File Descriptors, so a path
/// that does not exist will not be added to the final Landlock sandbox.
/// This is contrary to the way it is done on macOS, where paths with write
/// access will always be included.
///
/// Called once in `prepare()`. The returned `PrecomputedSandbox` is
/// cloned into the `pre_exec` closure.
#[cfg(target_os = "linux")]
pub fn precompute(policy: LandlockPolicy) -> Result<PrecomputedSandbox, String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let abi_version = check_availability()?;
    let seccomp_filter = build_seccomp_filter();
    if abi_version < ABI::V4 && policy.restrict_net_connect {
        // Check if proxy is configured (proxy_port would have been added to net_rules)
        let has_proxy = policy.net_rules.iter().any(|r| r.port != 443);
        if has_proxy {
            ui::warn(&format!(
                "Landlock ABI v{abi_version} (kernel < 6.7): \
                 TCP port filtering unavailable. Network security provided by proxy only."
            ));
        } else {
            ui::error(&format!(
                "WARNING: Landlock ABI v{abi_version} (kernel < 6.7) \
                 and no proxy configured — outbound network is UNRESTRICTED. \
                 Use --with-proxy or upgrade to kernel 6.7+ for network isolation."
            ));
        }
    }

    // Pre-create writable HOME_TOOL_DIRS cache directories that may not exist yet.
    // Landlock requires open(O_PATH) to succeed, so non-existent paths are
    // silently skipped. Writable cache dirs (e.g. ~/.cargo/registry) are
    // expected to be created on first use by build tools — we ensure they
    // exist so the Landlock rule can be applied and the sandboxed process
    // can actually write there.
    //
    // Scope: only HOME_TOOL_DIRS with write=true (build caches). We do NOT
    // pre-create user --allow-write paths, socket paths, or arbitrary writable
    // rules — those require the user to set up the filesystem themselves.
    for dir in policy::home_tool_dirs() {
        if dir.write {
            let path = policy.home_dir.join(dir.path);
            if !path.exists() {
                let _ = std::fs::create_dir_all(&path);
            }
        }
    }

    // Pre-open all filesystem paths in the parent process.
    // This avoids CString allocation and open() calls in pre_exec.
    // Paths under /proc/self are magic symlinks that resolve to /proc/<pid> —
    // the parent's pid, not the child's. Defer those to apply_precomputed().
    let mut pre_opened_fds = Vec::new();
    let mut deferred_paths = Vec::new();
    for rule in &policy.fs_rules {
        let c_path = CString::new(rule.path.as_os_str().as_bytes())
            .map_err(|_| format!("Path contains null byte: {}", rule.path.display()))?;
        if rule.path.starts_with("/proc/self") {
            deferred_paths.push((c_path, rule.access));
            continue;
        }
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd >= 0 {
            pre_opened_fds.push((fd, rule.access));
        }
        // Skip paths that don't exist (fd < 0) — the tool may not be installed.
    }

    let net_rules = policy.net_rules.clone();
    let restrict_net_connect = policy.restrict_net_connect;

    Ok(PrecomputedSandbox {
        abi_version,
        pre_opened_fds,
        deferred_paths,
        net_rules,
        restrict_net_connect,
        seccomp_filter,
    })
}

/// Build the seccomp BPF filter program in the parent process.
///
/// Returns a Vec of BPF instructions ready to be passed to prctl()
/// in the child. No allocation needed in pre_exec.
///
/// Security: The filter validates `seccomp_data.arch` first to prevent
/// bypass via 32-bit compat syscall ABI (e.g. `int 0x80` on x86_64).
#[cfg(target_os = "linux")]
fn build_seccomp_filter() -> Vec<BpfInstruction> {
    // BPF constants
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const EPERM_VAL: u32 = 1;

    // seccomp_data field offsets
    const NR_OFFSET: u32 = 0;
    const ARCH_OFFSET: u32 = 4;

    // Expected architecture audit values
    #[cfg(target_arch = "x86_64")]
    const EXPECTED_ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const EXPECTED_ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64

    const fn stmt(code: u16, k: u32) -> BpfInstruction {
        BpfInstruction {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> BpfInstruction {
        BpfInstruction { code, jt, jf, k }
    }

    // Blocked syscall numbers — privilege escalation and system modification
    // syscalls that a sandboxed code assistant should never need.
    // `mut` is needed on x86_64 where we push additional arch-specific entries below.
    #[allow(unused_mut)]
    let mut blocked: Vec<u32> = vec![
        libc::SYS_ptrace as u32,
        libc::SYS_process_vm_readv as u32,
        libc::SYS_process_vm_writev as u32,
        libc::SYS_mount as u32,
        libc::SYS_umount2 as u32,
        libc::SYS_unshare as u32,
        libc::SYS_setns as u32,
        libc::SYS_pivot_root as u32,
        libc::SYS_chroot as u32,
        libc::SYS_kexec_load as u32,
        libc::SYS_init_module as u32,
        libc::SYS_finit_module as u32,
        libc::SYS_delete_module as u32,
        libc::SYS_reboot as u32,
        libc::SYS_swapon as u32,
        libc::SYS_swapoff as u32,
        libc::SYS_personality as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_request_key as u32,
        libc::SYS_add_key as u32,
        libc::SYS_io_uring_setup as u32,
        libc::SYS_io_uring_enter as u32,
        libc::SYS_io_uring_register as u32,
        libc::SYS_userfaultfd as u32,
        libc::SYS_perf_event_open as u32,
        libc::SYS_bpf as u32,
    ];

    // x86_64-only syscalls — these don't exist on aarch64.
    #[cfg(target_arch = "x86_64")]
    {
        blocked.push(libc::SYS_iopl as u32);
        blocked.push(libc::SYS_ioperm as u32);
        blocked.push(libc::SYS_modify_ldt as u32);
    }

    let mut filter = Vec::with_capacity(blocked.len() * 2 + 4);

    // Step 1: Validate architecture — prevent bypass via compat syscall ABI.
    // If arch doesn't match, return EPERM for all syscalls.
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, ARCH_OFFSET));
    filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0));
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM_VAL));

    // Step 2: Load syscall number and check against blocklist.
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET));

    // For each blocked syscall: compare and jump to EPERM if match
    for &nr in &blocked {
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM_VAL));
    }

    // Default: allow
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    filter
}

/// Apply the pre-computed sandbox to the current process.
///
/// Called in the child's `pre_exec` hook. File descriptors are pre-opened
/// and BPF instructions pre-built in the parent via `precompute()`.
///
/// # Safety (async-signal-safety)
///
/// The Landlock crate API does heap-allocate internally (Ruleset, add_rule,
/// etc.). This runs after fork() in a multi-threaded process (the proxy
/// thread is running). Strictly, heap allocation in pre_exec is not
/// async-signal-safe. In practice this is safe because:
/// 1. The proxy thread spends nearly all time blocked in I/O syscalls
///    (epoll_wait/recv/send), not holding the allocator lock.
/// 2. The Landlock allocations are small and fast (~microseconds).
/// 3. This is the same risk profile as any Rust program using
///    Command::spawn() with pre_exec in a multi-threaded context.
///
/// Deferred paths (magic symlinks like `/proc/self`) also require one
/// `open()` call per path in the child.
/// The risk profile is the same as the heap allocation above.
///
/// The seccomp filter application is allocation-free (raw prctl syscall).
#[cfg(target_os = "linux")]
pub fn apply_precomputed(sandbox: &PrecomputedSandbox) -> std::io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };

    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(sandbox.abi_version))
        .map_err(std::io::Error::other)?;

    // Handle ConnectTcp on ABI v4+ only when network restriction is enabled.
    // When allow_localhost_any is set, we skip this — Landlock cannot
    // distinguish localhost from remote, so we rely on the proxy instead.
    let ruleset = if sandbox.abi_version >= ABI::V4 && sandbox.restrict_net_connect {
        ruleset
            .handle_access(AccessNet::ConnectTcp)
            .map_err(std::io::Error::other)?
    } else {
        ruleset
    };

    let mut created = ruleset.create().map_err(std::io::Error::other)?;

    // Add filesystem rules for deferred paths (e.g. /proc/self).
    // These are magic symlinks that resolve per-process — opened here in the
    // child so /proc/self resolves to the child's pid, not the parent's.
    // Deferred paths should only be used in special cases (such as /proc/self),
    // and are probably required for proper operation so failing to open is an error.
    for (c_path, access) in &sandbox.deferred_paths {
        let raw_fd: RawFd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let path_beneath_rule = create_path_beneath_rule(sandbox.abi_version, &raw_fd, access);
        created = created
            .add_rule(path_beneath_rule)
            .map_err(std::io::Error::other)?;
    }

    // Add filesystem rules using pre-opened file descriptors.
    // No open() or CString allocation — just borrow the raw fd.
    for &(raw_fd, access) in &sandbox.pre_opened_fds {
        let path_beneath_rule = create_path_beneath_rule(sandbox.abi_version, &raw_fd, &access);
        created = created
            .add_rule(path_beneath_rule)
            .map_err(std::io::Error::other)?;
    }

    // Add network rules (ABI v4+, only when network restriction is active).
    if sandbox.abi_version >= ABI::V4 && sandbox.restrict_net_connect {
        for rule in &sandbox.net_rules {
            created = created
                .add_rule(NetPort::new(rule.port, AccessNet::ConnectTcp))
                .map_err(std::io::Error::other)?;
        }
    }

    // Apply Landlock — this is irreversible.
    let status = created.restrict_self().map_err(std::io::Error::other)?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(std::io::Error::other(
            "Landlock rules were not enforced by the kernel",
        ));
    }

    // Apply pre-built seccomp filter.
    apply_seccomp_filter(&sandbox.seccomp_filter)?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn create_path_beneath_rule<'fd>(
    abi_version: ABI,
    raw_fd: &'fd RawFd,
    access: &FsAccess,
) -> PathBeneath<BorrowedFd<'fd>> {
    use std::os::fd::BorrowedFd;

    use landlock::{AccessFs, PathBeneath};

    let mut access_flags = if access.read {
        AccessFs::ReadFile | AccessFs::ReadDir
    } else {
        landlock::BitFlags::EMPTY
    };

    if access.write {
        let mut write_flags = AccessFs::WriteFile
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSym
            | AccessFs::MakeFifo
            | AccessFs::MakeSock;
        if abi_version >= ABI::V2 {
            // Refer controls rename()/link() across different Landlock
            // domains. Without it, build tools (cargo, git) that move
            // files between directories would fail.
            write_flags |= AccessFs::Refer;
        }
        if abi_version >= ABI::V3 {
            write_flags |= AccessFs::Truncate;
        }
        access_flags |= write_flags;
    }

    if access.execute {
        access_flags |= AccessFs::Execute;
    }

    if access.ioctl && abi_version >= ABI::V5 {
        // Landlock ABI v5 (kernel ≥ 6.8) enforces IOCTL_DEV for character
        // and block devices. Grant it for device paths so tcsetattr() on
        // /dev/tty and /dev/pts/* succeeds — without this, raw mode fails,
        // the terminal stays in cooked/echo mode and Copilot's TUI hangs.
        access_flags |= AccessFs::IoctlDev;
    }

    // Safety: raw_fd was opened in precompute() and is still valid
    // (O_CLOEXEC keeps it alive until exec, fork inherits it).
    let fd = unsafe { BorrowedFd::borrow_raw(*raw_fd) };
    PathBeneath::new(fd, access_flags)
}

/// Apply a pre-built seccomp BPF filter via prctl.
///
/// The filter must be constructed by `build_seccomp_filter()` in the
/// parent process. This function only makes one syscall.
#[cfg(target_os = "linux")]
fn apply_seccomp_filter(filter: &[BpfInstruction]) -> std::io::Result<()> {
    #[repr(C)]
    struct SockFprog {
        len: libc::c_ushort,
        filter: *const BpfInstruction,
    }

    let prog = SockFprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr(),
    };

    // PR_SET_NO_NEW_PRIVS is already set by Landlock's restrict_self().
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &raw const prog,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Names of blocked syscalls for display/testing purposes.
/// Cross-architecture names only — x86_64-specific syscalls are appended
/// via `blocked_syscall_names()` to match `build_seccomp_filter()`.
const BLOCKED_SYSCALL_NAMES_COMMON: &[&str] = &[
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "mount",
    "umount2",
    "unshare",
    "setns",
    "pivot_root",
    "chroot",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "swapon",
    "swapoff",
    "personality",
    "keyctl",
    "request_key",
    "add_key",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "userfaultfd",
    "perf_event_open",
    "bpf",
];

/// Return the full list of blocked syscall names for the current architecture.
pub fn blocked_syscall_names() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names = BLOCKED_SYSCALL_NAMES_COMMON.to_vec();
    #[cfg(target_arch = "x86_64")]
    {
        names.extend_from_slice(&["iopl", "ioperm", "modify_ldt"]);
    }
    names
}

// ── Tests (cross-platform) ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Build a minimal SandboxConfig for testing.
    fn test_config<'a>(
        project_dir: &'a Path,
        home_dir: &'a Path,
    ) -> super::super::SandboxConfig<'a> {
        super::super::SandboxConfig {
            project_dir,
            home_dir,
            extra_read: &[],
            extra_write: &[],
            extra_deny: &[],
            existing_home_tool_dirs: None,
            existing_app_dirs: None,
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            java_home: None,
            git_hooks_path: None,
            git_common_dir: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            allow_jvm_attach: false,
            allow_docker: false,
            electron_app_dir: None,
            agent: crate::agent::Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
        }
    }

    #[test]
    fn project_dir_gets_full_access() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == project)
            .expect("project dir should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
        assert!(rule.access.execute);
    }

    #[test]
    fn denied_dotfiles_not_in_ruleset() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for dotfile in policy::DENIED_DOTFILES {
            let path = home.join(dotfile);
            let found = policy.fs_rules.iter().any(|r| r.path == path);
            assert!(!found, "denied dotfile {dotfile} should NOT be in ruleset");
        }
    }

    #[test]
    fn denied_files_not_in_ruleset() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for file in policy::DENIED_FILES {
            let path = home.join(file);
            let found = policy.fs_rules.iter().any(|r| r.path == path);
            assert!(!found, "denied file {file} should NOT be in ruleset");
        }
    }

    /// DENIED_HOME_SUBPATHS (credential files inside allowed tool dirs) are NOT
    /// individually enforceable on Linux because Landlock cannot deny subpaths
    /// within allowed directories. The parent dirs (.m2, .gradle, .cargo) are
    /// allowed for dependency resolution — accepting this as a known limitation.
    /// macOS enforces these via literal SBPL deny rules (last-match-wins).
    #[test]
    fn denied_home_subpaths_not_enforceable_on_linux() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        // These files live inside allowed HOME_TOOL_DIRS — Landlock grants access
        // to the parent dir, and there's no mechanism to carve out individual files.
        for file in policy::DENIED_HOME_SUBPATHS {
            let path = home.join(file);
            // The file itself shouldn't have a direct rule (no explicit allow or deny)
            let has_direct_rule = policy.fs_rules.iter().any(|r| r.path == path);
            assert!(
                !has_direct_rule,
                "DENIED_HOME_SUBPATHS file {file} should NOT have a direct Landlock rule"
            );
        }
    }

    #[test]
    fn system_read_paths_are_readonly() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for &p in LINUX_SYSTEM_READ_PATHS {
            let rule = policy
                .fs_rules
                .iter()
                .find(|r| r.path == Path::new(p))
                .unwrap_or_else(|| panic!("system path {p} should be in rules"));
            assert!(rule.access.read, "{p} should have read");
            assert!(!rule.access.write, "{p} should NOT have write");
            assert!(!rule.access.execute, "{p} should NOT have execute");
        }
    }

    #[test]
    fn tool_dirs_have_read_and_execute() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for &p in LINUX_TOOL_DIRS {
            let rule = policy
                .fs_rules
                .iter()
                .find(|r| r.path == Path::new(p))
                .unwrap_or_else(|| panic!("tool dir {p} should be in rules"));
            assert!(rule.access.read, "{p} should have read");
            assert!(!rule.access.write, "{p} should NOT have write");
            assert!(rule.access.execute, "{p} should have execute");
        }
    }

    #[test]
    fn home_tool_dirs_permissions_match() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for dir in policy::home_tool_dirs() {
            let path = home.join(dir.path);
            let rule = policy
                .fs_rules
                .iter()
                .find(|r| r.path == path)
                .unwrap_or_else(|| panic!("home tool dir {} should be in rules", dir.path));
            assert!(rule.access.read, "{} should have read", dir.path);
            assert_eq!(rule.access.write, dir.write, "{} write mismatch", dir.path);
            assert_eq!(
                rule.access.execute,
                dir.process_exec || dir.map_exec,
                "{} execute mismatch",
                dir.path
            );
        }
    }

    #[test]
    fn scratch_dir_always_has_exec() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let scratch = PathBuf::from("/home/user/.cache/cplt/tmp/session-1");

        // Scratch dir should always have exec, regardless of allow_tmp_exec.
        // The scratch dir is the controlled alternative to /tmp for
        // compile-then-exec workflows (node-gyp, cargo).
        let mut config = test_config(&project, &home);
        config.scratch_dir = Some(&scratch);
        config.allow_tmp_exec = false;
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == scratch)
            .expect("scratch dir should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
        assert!(
            rule.access.execute,
            "scratch dir should always have exec (independent of allow_tmp_exec)"
        );
    }

    #[test]
    fn extra_read_paths_added() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let extra = vec![PathBuf::from("/mnt/data")];
        let mut config = test_config(&project, &home);
        config.extra_read = &extra;
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/mnt/data"))
            .expect("extra read path should be in rules");
        assert!(rule.access.read);
        assert!(!rule.access.write);
        assert!(!rule.access.execute);
    }

    #[test]
    fn extra_write_paths_added() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let extra = vec![PathBuf::from("/mnt/output")];
        let mut config = test_config(&project, &home);
        config.extra_write = &extra;
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/mnt/output"))
            .expect("extra write path should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
    }

    #[test]
    fn proxy_port_added_to_net_rules() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.proxy_port = Some(8080);
        let policy = generate_policy(&config);

        assert!(policy.net_rules.iter().any(|r| r.port == 8080));
    }

    #[test]
    fn extra_ports_added_to_net_rules() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let ports = vec![443, 8443];
        let mut config = test_config(&project, &home);
        config.extra_ports = &ports;
        let policy = generate_policy(&config);

        assert!(policy.net_rules.iter().any(|r| r.port == 443));
        assert!(policy.net_rules.iter().any(|r| r.port == 8443));
    }

    #[test]
    fn localhost_ports_in_net_rules() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let ports = vec![3000, 5173];
        let mut config = test_config(&project, &home);
        config.localhost_ports = &ports;
        let policy = generate_policy(&config);

        assert!(policy.net_rules.iter().any(|r| r.port == 3000));
        assert!(policy.net_rules.iter().any(|r| r.port == 5173));
        assert!(policy.restrict_net_connect);
    }

    #[test]
    fn allow_localhost_any_disables_net_connect_restriction() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.allow_localhost_any = true;
        let policy = generate_policy(&config);

        // Net rules are still populated (used for display) but restriction is off
        assert!(!policy.restrict_net_connect);
    }

    #[test]
    fn default_config_restricts_net_connect() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        assert!(policy.restrict_net_connect);
        assert!(policy.net_rules.iter().any(|r| r.port == 443));
    }

    #[test]
    fn discovery_filtering_limits_home_tool_dirs() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let existing = vec![
            ".cargo/bin".to_string(),
            ".cargo/registry".to_string(),
            ".cargo/git".to_string(),
            ".nvm".to_string(),
        ];
        let mut config = test_config(&project, &home);
        config.existing_home_tool_dirs = Some(&existing);
        let policy = generate_policy(&config);

        // .cargo/bin and .nvm should be present
        assert!(
            policy
                .fs_rules
                .iter()
                .any(|r| r.path == home.join(".cargo/bin"))
        );
        assert!(policy.fs_rules.iter().any(|r| r.path == home.join(".nvm")));

        // .pyenv should NOT be present (not in discovery list)
        assert!(
            !policy
                .fs_rules
                .iter()
                .any(|r| r.path == home.join(".pyenv"))
        );
    }

    #[test]
    fn gpg_signing_adds_specific_files() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.allow_gpg_signing = true;
        let policy = generate_policy(&config);

        // Public key files should be read-only
        let pubring = home.join(".gnupg/pubring.kbx");
        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == pubring)
            .expect("pubring.kbx should be in rules");
        assert!(rule.access.read);
        assert!(!rule.access.write);

        // Agent socket should be read+write
        let socket = home.join(".gnupg/S.gpg-agent");
        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == socket)
            .expect("gpg-agent socket should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
    }

    #[test]
    fn gpg_signing_off_excludes_gnupg() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let gnupg_rules: Vec<_> = policy
            .fs_rules
            .iter()
            .filter(|r| r.path.starts_with(home.join(".gnupg")))
            .collect();
        assert!(
            gnupg_rules.is_empty(),
            "gnupg paths should not be in rules when gpg signing is off"
        );
    }

    #[test]
    fn copilot_install_dir_gets_read_exec() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let install_dir = PathBuf::from("/home/user/.cache/copilot/pkg/linux-x64");
        let mut config = test_config(&project, &home);
        config.copilot_install_dir = Some(&install_dir);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == install_dir)
            .expect("copilot install dir should be in rules");
        assert!(rule.access.read);
        assert!(!rule.access.write);
        assert!(rule.access.execute);
    }

    #[test]
    fn tmp_no_exec_by_default() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/tmp"))
            .expect("/tmp should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
        assert!(
            !rule.access.execute,
            "/tmp should not have execute by default"
        );
    }

    #[test]
    fn jvm_attach_grants_tmp_exec_and_proc_read() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.allow_jvm_attach = true;
        let policy = generate_policy(&config);

        let tmp_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/tmp"))
            .expect("/tmp should be in rules");
        assert!(
            tmp_rule.access.execute,
            "/tmp should have execute when allow_jvm_attach is true"
        );

        let proc_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/proc"))
            .expect("/proc should be in rules when allow_jvm_attach is true");
        assert!(proc_rule.access.read, "/proc should have read");
        assert!(!proc_rule.access.write, "/proc should not have write");
        assert!(!proc_rule.access.execute, "/proc should not have execute");
    }

    #[test]
    fn device_files_have_read_write() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for &dev in DEVICE_FILES {
            let rule = policy
                .fs_rules
                .iter()
                .find(|r| r.path == Path::new(dev))
                .unwrap_or_else(|| panic!("device {dev} should be in rules"));
            assert!(rule.access.read, "{dev} should have read");
            assert!(rule.access.write, "{dev} should have write");
            assert!(!rule.access.execute, "{dev} should NOT have execute");
        }
    }

    #[test]
    fn proc_self_is_readonly() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == Path::new("/proc/self"))
            .expect("/proc/self should be in rules");
        assert!(rule.access.read);
        assert!(!rule.access.write);
        assert!(!rule.access.execute);
    }

    #[test]
    fn describe_policy_includes_all_sections() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.proxy_port = Some(8080);
        let policy = generate_policy(&config);
        let desc = describe_policy(&policy);

        assert!(desc.contains("deny-by-default"));
        assert!(desc.contains("Full access"));
        assert!(desc.contains("/home/user/project"));
        assert!(desc.contains("Read + execute"));
        assert!(desc.contains("Read only"));
        assert!(desc.contains("Network"));
        assert!(desc.contains("port 8080"));
        assert!(desc.contains("allowlist-only"));
    }

    #[test]
    fn describe_policy_shows_unrestricted_when_localhost_any() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.allow_localhost_any = true;
        let policy = generate_policy(&config);
        let desc = describe_policy(&policy);

        assert!(desc.contains("UNRESTRICTED"));
        assert!(desc.contains("--allow-localhost-any"));
    }

    #[test]
    fn blocked_syscall_names_not_empty() {
        let names = blocked_syscall_names();
        assert!(
            names.len() >= 26,
            "should block at least 26 dangerous syscalls, got {}",
            names.len()
        );
    }

    #[test]
    fn home_config_files_are_readable() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for &file in LINUX_HOME_CONFIG_FILES {
            let path = home.join(file);
            let rule = policy
                .fs_rules
                .iter()
                .find(|r| r.path == path)
                .unwrap_or_else(|| panic!("home config file {file} should be in rules"));
            assert!(rule.access.read, "{file} should have read");
            assert!(!rule.access.write, "{file} should NOT have write");
            assert!(!rule.access.execute, "{file} should NOT have execute");
        }

        // $HOME itself must NOT be in the ruleset (would grant recursive read)
        assert!(
            !policy.fs_rules.iter().any(|r| r.path == home),
            "$HOME must not have a blanket rule (Landlock is recursive)"
        );
    }

    #[test]
    fn copilot_config_dir_is_writable_and_executable() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".copilot"))
            .expect(".copilot dir should be in rules");
        assert!(rule.access.read);
        assert!(rule.access.write);
        assert!(
            rule.access.execute,
            ".copilot needs execute for native .node module dlopen()"
        );
    }

    #[test]
    fn copilot_dir_absent_for_non_copilot_agent() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        config.agent = crate::agent::Agent::OpenCode;
        let policy = generate_policy(&config);

        assert!(
            !policy
                .fs_rules
                .iter()
                .any(|r| r.path == home.join(".copilot")),
            ".copilot should NOT be in rules for non-Copilot agent"
        );
    }

    #[test]
    fn agent_dirs_added_to_policy() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let agent_dirs = vec![
            crate::agent::AgentDir {
                path: home.join(".config/opencode"),
                write: false,
                map_exec: false,
                process_exec: false,
                write_files: vec!["auth.json"],
            },
            crate::agent::AgentDir {
                path: home.join(".local/share/opencode"),
                write: true,
                map_exec: false,
                process_exec: false,
                write_files: vec![],
            },
            crate::agent::AgentDir {
                path: home.join(".local/state/opencode"),
                write: true,
                map_exec: false,
                process_exec: false,
                write_files: vec![],
            },
            crate::agent::AgentDir {
                path: home.join(".cache/opencode"),
                write: true,
                map_exec: false,
                process_exec: false,
                write_files: vec![],
            },
            crate::agent::AgentDir {
                path: home.join(".cache/opencode/bin"),
                write: false,
                map_exec: false,
                process_exec: true,
                write_files: vec![],
            },
        ];
        let mut config = test_config(&project, &home);
        config.agent = crate::agent::Agent::OpenCode;
        config.agent_dirs = &agent_dirs;
        let policy = generate_policy(&config);

        let config_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".config/opencode"))
            .expect("OpenCode config dir should be in rules");
        assert!(config_rule.access.read);
        assert!(!config_rule.access.write, "config dir should be read-only");

        // write_files should generate a separate rule for auth.json
        let auth_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".config/opencode/auth.json"))
            .expect("auth.json should have its own rule");
        assert!(auth_rule.access.read);
        assert!(auth_rule.access.write, "auth.json should be writable");
        assert!(
            !auth_rule.access.execute,
            "auth.json should NOT be executable"
        );

        let data_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".local/share/opencode"))
            .expect("OpenCode data dir should be in rules");
        assert!(data_rule.access.read);
        assert!(data_rule.access.write, "data dir should be writable");
        assert!(
            !data_rule.access.execute,
            "data dir should NOT be executable"
        );

        let state_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".local/state/opencode"))
            .expect("OpenCode state data dir should be in rules");
        assert!(state_rule.access.read);
        assert!(state_rule.access.write, "state data dir should be writable");
        assert!(
            !state_rule.access.execute,
            "state data dir should NOT be executable"
        );

        let cache_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".cache/opencode"))
            .expect("OpenCode cache dir should be in rules");
        assert!(cache_rule.access.read);
        assert!(cache_rule.access.write, "cache dir should be writable");

        let bin_rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home.join(".cache/opencode/bin"))
            .expect("OpenCode cache/bin should be in rules");
        assert!(bin_rule.access.read);
        assert!(!bin_rule.access.write, "cache/bin should NOT be writable");
        assert!(
            bin_rule.access.execute,
            "cache/bin should be executable (managed tools)"
        );
    }

    #[test]
    fn app_dirs_included_when_existing_is_none() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        // Resolve at least one mise app dir path; skip if no home dir
        let mise_paths: Vec<PathBuf> = policy::app_dirs()[0].all_paths(&home);
        if mise_paths.is_empty() {
            return;
        }

        let found = mise_paths
            .iter()
            .any(|p| policy.fs_rules.iter().any(|r| &r.path == p));
        assert!(
            found,
            "With existing_app_dirs=None, at least one mise app dir path should appear in policy"
        );
    }

    #[test]
    fn app_dirs_excluded_when_no_match() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let mut config = test_config(&project, &home);
        let nonexistent = vec!["/nonexistent".to_string()];
        config.existing_app_dirs = Some(&nonexistent);
        let policy = generate_policy(&config);

        // Some mise paths may appear from LINUX_HOME_CONFIG_FILES (read-only).
        // The important property is that writable app-dir paths are excluded.
        let write_paths = policy::app_dirs()[0].write_paths(&home);
        for p in &write_paths {
            assert!(
                !policy
                    .fs_rules
                    .iter()
                    .any(|r| &r.path == p && r.access.write),
                "With non-matching existing_app_dirs, mise write path {} should NOT appear in policy with write access",
                p.display()
            );
        }
        // Also verify process_exec paths are not granted execute
        let exec_paths = policy::app_dirs()[0].process_exec_paths(&home);
        for p in &exec_paths {
            assert!(
                !policy
                    .fs_rules
                    .iter()
                    .any(|r| &r.path == p && r.access.execute),
                "With non-matching existing_app_dirs, mise exec path {} should NOT appear in policy with execute",
                p.display()
            );
        }
    }

    #[test]
    fn app_dir_fsaccess_flags_match_permissions() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let mise = &policy::app_dirs()[0];
        let all_paths = mise.all_paths(&home);
        if all_paths.is_empty() {
            return;
        }

        let write_paths = mise.write_paths(&home);
        let process_exec_paths = mise.process_exec_paths(&home);
        let map_exec_paths = mise.map_exec_paths(&home);
        let read_paths = mise.read_paths(&home);

        for path in &all_paths {
            let rule = policy.fs_rules.iter().find(|r| &r.path == path);
            let Some(rule) = rule else {
                panic!(
                    "missing FsRule for expected app-dir path {}",
                    path.display()
                );
            };

            if write_paths.contains(path) {
                assert!(
                    rule.access.write,
                    "path {} is in write_paths but FsRule.write is false",
                    path.display()
                );
            }

            if process_exec_paths.contains(path) || map_exec_paths.contains(path) {
                assert!(
                    rule.access.execute,
                    "path {} is in exec paths but FsRule.execute is false",
                    path.display()
                );
            }

            if read_paths.contains(path) {
                assert!(
                    rule.access.read,
                    "path {} is in read_paths but FsRule.read is false",
                    path.display()
                );
            } else {
                assert!(
                    !rule.access.read,
                    "path {} is NOT in read_paths but FsRule.read is true",
                    path.display()
                );
            }

            if read_paths.contains(path)
                && !write_paths.contains(path)
                && !process_exec_paths.contains(path)
                && !map_exec_paths.contains(path)
            {
                assert!(
                    !rule.access.write,
                    "path {} is read-only but FsRule.write is true",
                    path.display()
                );
                assert!(
                    !rule.access.execute,
                    "path {} is read-only but FsRule.execute is true",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn app_dir_effective_permissions_include_parent_rules() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        for app_dir in policy::app_dirs() {
            let all_paths = app_dir.all_paths(&home);
            if all_paths.is_empty() {
                continue;
            }

            let write_paths = app_dir.write_paths(&home);
            let process_exec_paths = app_dir.process_exec_paths(&home);
            let map_exec_paths = app_dir.map_exec_paths(&home);

            for path in &all_paths {
                // Compute effective access by OR-ing all rules whose path is an ancestor of
                // or equal to the target path (Landlock rules apply to path and its subtree).
                let mut effective_read = false;
                let mut effective_write = false;
                let mut effective_execute = false;
                for rule in &policy.fs_rules {
                    if path.starts_with(&rule.path) {
                        effective_read |= rule.access.read;
                        effective_write |= rule.access.write;
                        effective_execute |= rule.access.execute;
                    }
                }

                assert!(
                    effective_read,
                    "app-dir path {} should have effective read access",
                    path.display()
                );

                if write_paths.contains(path) {
                    assert!(
                        effective_write,
                        "app-dir path {} declares write but effective write is false",
                        path.display()
                    );
                }

                if process_exec_paths.contains(path) || map_exec_paths.contains(path) {
                    assert!(
                        effective_execute,
                        "app-dir path {} declares exec but effective execute is false",
                        path.display()
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_self_is_deferred_not_pre_opened() {
        let policy = LandlockPolicy {
            fs_rules: vec![
                FsRule {
                    path: PathBuf::from("/proc/self"),
                    access: FsAccess {
                        read: true,
                        write: false,
                        execute: false,
                        ioctl: false,
                    },
                },
                FsRule {
                    path: PathBuf::from("/tmp"),
                    access: FsAccess {
                        read: true,
                        write: false,
                        execute: false,
                        ioctl: false,
                    },
                },
            ],
            net_rules: vec![],
            restrict_net_connect: false,
            home_dir: PathBuf::from("/tmp/test-home"),
        };

        let precomputed = precompute(policy).expect("precompute should succeed");

        assert_eq!(
            precomputed.deferred_paths.len(),
            1,
            "exactly one path should be deferred"
        );
        let (c_path, _) = &precomputed.deferred_paths[0];
        assert_eq!(
            c_path.to_str().unwrap(),
            "/proc/self",
            "/proc/self should be in deferred_paths"
        );

        assert_eq!(
            precomputed.pre_opened_fds.len(),
            1,
            "/tmp should be pre-opened; /proc/self must not be"
        );
    }
}
