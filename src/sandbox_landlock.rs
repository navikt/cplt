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
//! The proxy handles domain-level filtering on both platforms.

use std::fmt::Write as _;
use std::path::PathBuf;

use super::policy::{self, HomeToolDir};

// ── Cross-platform types ───────────────────────────────────────

/// Filesystem access flags for a Landlock rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsAccess {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
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
}

/// Pre-computed data for sandbox application in the child process.
///
/// Everything here is computed in the parent (where allocation and I/O
/// are safe). The `pre_exec` hook only receives this immutable data and
/// makes raw syscalls — no allocation, no file I/O.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct PrecomputedSandbox {
    pub abi_version: u32,
    pub policy: LandlockPolicy,
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

/// Home tool directories for Linux.
///
/// Shares most entries with macOS HOME_TOOL_DIRS (in sandbox_policy.rs)
/// but replaces macOS-specific `Library/Caches` and `Library/pnpm` with
/// their Linux equivalents.
const LINUX_HOME_TOOL_DIRS: &[HomeToolDir] = &[
    // ── Shared with macOS (same paths, same permissions) ──
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
    HomeToolDir {
        path: ".yarn",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    // ── Linux-specific (replaces macOS Library/* paths) ──
    HomeToolDir {
        path: ".cache",
        process_exec: false,
        map_exec: false,
        write: true,
    },
    HomeToolDir {
        path: ".local/share/pnpm",
        process_exec: true,
        map_exec: true,
        write: true,
    },
    // ── Linux-only runtimes ──
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
];

/// Device and pseudo-filesystem paths that Node.js and common tools need.
const DEVICE_FILES: &[&str] = &[
    "/dev/null",
    "/dev/urandom",
    "/dev/zero",
    "/dev/random",
    "/dev/tty", // Terminal device (interactive tools)
    "/dev/pts", // Pseudo-terminal devices
    "/dev/shm", // POSIX shared memory (Node.js, Chromium)
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
            },
        });
    }

    // ── Home tool directories (filtered by discovery) ──
    for dir in LINUX_HOME_TOOL_DIRS {
        if should_include_tool_dir(dir, config) {
            fs_rules.push(FsRule {
                path: home.join(dir.path),
                access: FsAccess {
                    read: true,
                    write: dir.write,
                    execute: dir.process_exec || dir.map_exec,
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
            },
        });
    }

    // ── Scratch directory: read + write, execute only if allowed ──
    if let Some(dir) = config.scratch_dir {
        fs_rules.push(FsRule {
            path: dir.to_path_buf(),
            access: FsAccess {
                read: true,
                write: true,
                execute: config.allow_tmp_exec,
            },
        });
    }

    // ── /tmp: read + write, execute only if explicitly allowed ──
    fs_rules.push(FsRule {
        path: PathBuf::from("/tmp"),
        access: FsAccess {
            read: true,
            write: true,
            execute: config.allow_tmp_exec,
        },
    });

    // ── Device files: read + write (no execute) ──
    for &dev in DEVICE_FILES {
        fs_rules.push(FsRule {
            path: PathBuf::from(dev),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
            },
        });
    }

    // ── /proc/self: Node.js reads /proc/self/exe, /proc/self/maps ──
    fs_rules.push(FsRule {
        path: PathBuf::from("/proc/self"),
        access: FsAccess {
            read: true,
            write: false,
            execute: false,
        },
    });

    // ── Extra read paths from config ──
    for p in config.extra_read {
        fs_rules.push(FsRule {
            path: p.clone(),
            access: FsAccess {
                read: true,
                write: false,
                execute: false,
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
                },
            });
        }
    }

    // ── Home dir itself: read-only for dotfile enumeration ──
    // Tools like Node.js resolve config by listing $HOME. Grant read
    // on the home dir itself (not recursively — Landlock is per-dir).
    fs_rules.push(FsRule {
        path: home.to_path_buf(),
        access: FsAccess {
            read: true,
            write: false,
            execute: false,
        },
    });

    // ── Copilot config dir: read + write ──
    // Copilot stores auth tokens and config in ~/.copilot/
    fs_rules.push(FsRule {
        path: home.join(".copilot"),
        access: FsAccess {
            read: true,
            write: true,
            execute: false,
        },
    });

    // ── Network rules (requires ABI v4+, kernel 6.7+) ──
    let mut net_rules = Vec::new();
    if let Some(port) = config.proxy_port {
        net_rules.push(NetRule { port });
    }
    for &port in config.extra_ports {
        net_rules.push(NetRule { port });
    }
    for &port in config.localhost_ports {
        net_rules.push(NetRule { port });
    }

    // Denied dotfiles and denied files are handled by simply NOT adding
    // them to the ruleset — Landlock is deny-by-default.
    //
    // Note: This means we cannot deny subpaths within an allowed tree
    // (e.g. .env files inside the project dir). Those protections come
    // from the proxy (blocks exfiltration) and env hardening (blocks
    // hook injection). See module-level doc comment.

    LandlockPolicy {
        fs_rules,
        net_rules,
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

    if !policy.net_rules.is_empty() {
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

/// Check Landlock availability and return the ABI version.
///
/// Reads `/sys/kernel/security/landlock/abi_version` to determine
/// which Landlock features the running kernel supports.
///
/// Called in the parent process during `prepare()` — never in `pre_exec`.
#[cfg(target_os = "linux")]
pub fn check_availability() -> Result<u32, String> {
    match std::fs::read_to_string("/sys/kernel/security/landlock/abi_version") {
        Ok(s) => {
            let version: u32 = s
                .trim()
                .parse()
                .map_err(|e| format!("Invalid Landlock ABI version: {e}"))?;
            if version < 1 {
                Err("Landlock ABI version 0 is not supported".to_string())
            } else {
                Ok(version)
            }
        }
        Err(e) => Err(format!(
            "Landlock is not available on this system: {e}\n\
             Requires Linux 5.13+ with Landlock enabled in the kernel.\n\
             Check: cat /sys/kernel/security/lsm (should include 'landlock')"
        )),
    }
}

/// Pre-compute all sandbox data in the parent process.
///
/// This does all I/O and allocation before fork(), so the `pre_exec`
/// hook only needs to make raw syscalls. This avoids async-signal-safety
/// issues when forking a multi-threaded process (the proxy thread may
/// be running).
///
/// Called once in `prepare()`. The returned `PrecomputedSandbox` is
/// cloned into the `pre_exec` closure.
#[cfg(target_os = "linux")]
pub fn precompute(policy: LandlockPolicy) -> Result<PrecomputedSandbox, String> {
    let abi_version = check_availability()?;
    let seccomp_filter = build_seccomp_filter();

    if abi_version < 4 {
        eprintln!(
            "\x1b[0;33m[cplt]\x1b[0m Landlock ABI v{abi_version} (kernel < 6.7): \
             TCP port filtering unavailable. Network security provided by proxy only."
        );
    }

    Ok(PrecomputedSandbox {
        abi_version,
        policy,
        seccomp_filter,
    })
}

/// Build the seccomp BPF filter program in the parent process.
///
/// Returns a Vec of BPF instructions ready to be passed to prctl()
/// in the child. No allocation needed in pre_exec.
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

    // Offset of `nr` field in seccomp_data struct
    const NR_OFFSET: u32 = 0;

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

    // Blocked syscall numbers (x86_64).
    // Privilege escalation and system modification syscalls
    // that a sandboxed code assistant should never need.
    let blocked: &[u32] = &[
        libc::SYS_ptrace as u32,
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
        libc::SYS_iopl as u32,
        libc::SYS_ioperm as u32,
        libc::SYS_modify_ldt as u32,
        libc::SYS_personality as u32,
        libc::SYS_keyctl as u32,
        libc::SYS_request_key as u32,
        libc::SYS_add_key as u32,
    ];

    let mut filter = Vec::with_capacity(blocked.len() * 2 + 2);

    // Load syscall number from seccomp_data.nr
    filter.push(stmt(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET));

    // For each blocked syscall: compare and jump to EPERM if match
    for &nr in blocked {
        filter.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM_VAL));
    }

    // Default: allow
    filter.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    filter
}

/// Apply the pre-computed sandbox to the current process.
///
/// Called in the child's `pre_exec` hook — all data is pre-computed,
/// so this function only makes raw syscalls (no allocation, no I/O).
///
/// # Safety context
///
/// Safe for `pre_exec` because:
/// - Landlock crate API internally uses only syscalls + stack structs
/// - PathFd::new() is just open() (async-signal-safe)
/// - Seccomp filter is pre-built; only prctl() is called here
/// - All error messages are static strings (no allocation)
#[cfg(target_os = "linux")]
pub fn apply_precomputed(sandbox: &PrecomputedSandbox) -> std::io::Result<()> {
    use landlock::{
        ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    let abi = ABI::V5;
    let abi_version = sandbox.abi_version;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Always handle ConnectTcp on ABI v4+ — even with empty rules this means
    // "deny all TCP connect" (deny-by-default for network).
    if abi_version >= 4 {
        ruleset
            .handle_access(AccessNet::ConnectTcp)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    let mut created = ruleset
        .create()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Add filesystem rules.
    for rule in &sandbox.policy.fs_rules {
        let mut access = if rule.access.read {
            AccessFs::ReadFile | AccessFs::ReadDir
        } else {
            landlock::BitFlags::EMPTY
        };

        if rule.access.write {
            let mut write_flags = AccessFs::WriteFile
                | AccessFs::RemoveDir
                | AccessFs::RemoveFile
                | AccessFs::MakeDir
                | AccessFs::MakeReg
                | AccessFs::MakeSym
                | AccessFs::MakeFifo
                | AccessFs::MakeSock;
            if abi_version >= 3 {
                write_flags |= AccessFs::Truncate;
            }
            access |= write_flags;
        }

        if rule.access.execute {
            access |= AccessFs::Execute;
        }

        // Skip paths that don't exist — the tool may not be installed.
        if let Ok(fd) = PathFd::new(&rule.path) {
            created
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
    }

    // Add network rules (ABI v4+).
    if abi_version >= 4 {
        for rule in &sandbox.policy.net_rules {
            created
                .add_rule(NetPort::new(rule.port, AccessNet::ConnectTcp))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        }
    }

    // Apply Landlock — this is irreversible.
    let status = created
        .restrict_self()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Landlock rules were not enforced by the kernel",
        ));
    }

    // Apply pre-built seccomp filter.
    apply_seccomp_filter(&sandbox.seccomp_filter)?;

    Ok(())
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
            &prog as *const SockFprog,
        )
    };

    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Names of blocked syscalls for display/testing purposes.
/// Matches the order in `apply_seccomp()`.
pub const BLOCKED_SYSCALL_NAMES: &[&str] = &[
    "ptrace",
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
    "iopl",
    "ioperm",
    "modify_ldt",
    "personality",
    "keyctl",
    "request_key",
    "add_key",
];

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
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            git_hooks_path: None,
            allow_gpg_signing: false,
            electron_app_dir: None,
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

        for dir in LINUX_HOME_TOOL_DIRS {
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
    fn scratch_dir_gets_write_and_conditional_exec() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let scratch = PathBuf::from("/home/user/.cache/cplt/tmp/session-1");

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
            !rule.access.execute,
            "exec should be off when allow_tmp_exec=false"
        );

        config.allow_tmp_exec = true;
        let policy = generate_policy(&config);
        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == scratch)
            .expect("scratch dir should be in rules");
        assert!(
            rule.access.execute,
            "exec should be on when allow_tmp_exec=true"
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
    }

    #[test]
    fn discovery_filtering_limits_home_tool_dirs() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let existing = vec![".cargo".to_string(), ".nvm".to_string()];
        let mut config = test_config(&project, &home);
        config.existing_home_tool_dirs = Some(&existing);
        let policy = generate_policy(&config);

        // .cargo and .nvm should be present
        assert!(
            policy
                .fs_rules
                .iter()
                .any(|r| r.path == home.join(".cargo"))
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
    fn blocked_syscall_names_not_empty() {
        assert!(
            BLOCKED_SYSCALL_NAMES.len() >= 20,
            "should block at least 20 dangerous syscalls"
        );
    }

    #[test]
    fn home_dir_itself_is_readable() {
        let project = PathBuf::from("/home/user/project");
        let home = PathBuf::from("/home/user");
        let config = test_config(&project, &home);
        let policy = generate_policy(&config);

        let rule = policy
            .fs_rules
            .iter()
            .find(|r| r.path == home)
            .expect("home dir should be in rules");
        assert!(rule.access.read);
        assert!(!rule.access.write);
        assert!(!rule.access.execute);
    }

    #[test]
    fn copilot_config_dir_is_writable() {
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
    }
}
