//! Bubblewrap namespace isolation for Linux.
//!
//! # What this actually guarantees
//!
//! Bubblewrap (`bwrap`) layers kernel **namespace** isolation on top of the
//! Landlock + seccomp-BPF sandbox. The honest guarantees are:
//!
//! - **PID namespace**: the agent cannot see or signal host processes (`ps`
//!   shows only the agent's own tree).
//! - **IPC / UTS / cgroup namespaces**: no shared SysV IPC, isolated hostname,
//!   isolated cgroup view.
//! - **User namespace**: unprivileged operation — the agent maps to the
//!   invoking UID and holds no real capabilities on the host.
//! - **Mount namespace**: the entire host filesystem is bind-mounted
//!   **read-only** (`--ro-bind / /`); writable paths are re-bound writable at
//!   their real locations. Actual *access control* is still Landlock's job
//!   (deny-by-default): the mount namespace only changes the mount topology,
//!   it does not hide arbitrary files.
//! - **Network**: the network namespace is **deliberately shared with the
//!   host** (no `--unshare-net`) so the agent can reach the host-bound cplt
//!   CONNECT proxy on `127.0.0.1`. Outbound control stays with Landlock TCP
//!   port rules (ABI v4+) and the proxy — bwrap adds nothing here.
//!
//! # Layering (how Landlock + seccomp stay enforced under bwrap)
//!
//! `bwrap` itself needs `unshare(2)`, `mount(2)` and `pivot_root(2)` to build
//! the namespaces. Our seccomp filter `EPERM`s exactly those syscalls and a
//! restrictive Landlock domain (deny-by-default, no rule for `/`) blocks the
//! bind-mount sources — so we must **not** apply either to the `bwrap` process.
//! Instead they are applied to the **agent**, after bwrap finishes its setup:
//!
//! ```text
//! cplt ──exec──▶ bwrap (namespaces only, unrestricted)
//!                  └─exec──▶ cplt re-entry helper (this module, in-namespace)
//!                              │  applies Landlock + seccomp bound to the
//!                              │  inodes visible *inside* the namespaces
//!                              └─execve──▶ agent (Landlock + seccomp enforced)
//! ```
//!
//! The re-entry helper is dispatched by an `.init_array` constructor
//! ([`bwrap_inner_entry`]) that runs before `main()`. On a normal cplt run the
//! constructor is a single `getenv` and returns immediately; it only does work
//! when this process is the bwrap-spawned helper (identified by the
//! [`ENV_INNER_POLICY`] environment variable). This lets the whole feature
//! live in the sandbox layer without any change to `main.rs`.
//!
//! Because the helper opens its Landlock `O_PATH` fds *inside* the namespaces,
//! Landlock binds to the exact inodes present there (the fresh `--proc`,
//! `--dev` and `--tmpfs /tmp` mounts and the mirrored writable binds) — making
//! the effective policy identical to the non-bwrap path. See
//! [`crate::sandbox::landlock_mod::apply_landlock_and_seccomp_now`].
//!
//! # Graceful degradation
//!
//! If `bwrap` is missing or namespace creation fails during
//! [`check_availability`]/[`test_functionality`], auto-detect falls back to
//! Landlock + seccomp only. If the wrapped process fails to signal that the
//! inner sandbox was applied (see the confirm pipe in `sandbox_exec.rs`),
//! auto-detect likewise falls back at spawn time rather than bricking the run.
//!
//! # Configuration
//!
//! Controlled by `use_bubblewrap` in `SandboxConfig`:
//! - `Some(true)`: always use bwrap (fail if unavailable)
//! - `Some(false)`: never use bwrap
//! - `None` (default): auto-detect and use if available

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::sandbox::landlock_mod::{FsAccess, FsRule, NetRule};

/// Environment variable carrying the read end of the policy pipe (a decimal fd
/// number) from which the bwrap re-entry helper reads the serialized Landlock
/// policy + agent argv. Its mere presence tells the `.init_array` constructor
/// that this process is the helper.
///
/// A pipe is used instead of a file deliberately: the namespaces mount a fresh
/// `--tmpfs /tmp`, so a policy file in the host temp dir could be invisible
/// inside; an inherited fd is immune to mount topology and leaves no policy
/// data on disk.
pub(crate) const ENV_INNER_POLICY: &str = "__CPLT_BWRAP_POLICY_FD";

/// Environment variable carrying the write end of the confirm pipe (a decimal
/// fd number). The helper writes one byte to it just before `execve`-ing the
/// agent so the parent knows the inner sandbox was applied.
pub(crate) const ENV_CONFIRM_FD: &str = "__CPLT_BWRAP_CONFIRM_FD";

/// A validated Bubblewrap execution wrapper, built during `prepare()`.
#[derive(Clone)]
pub(crate) struct BubblewrapWrapper {
    /// Path to the `bwrap` binary.
    pub bwrap_path: PathBuf,
    /// Pre-built namespace/mount arguments for `bwrap` (before `-- <helper>`).
    pub bwrap_args: Vec<String>,
    /// Landlock filesystem rules, re-applied in-namespace by the helper.
    pub fs_rules: Vec<FsRule>,
    /// Landlock TCP-connect rules, re-applied in-namespace by the helper.
    pub net_rules: Vec<NetRule>,
    /// Whether to restrict TCP connect at the kernel level.
    pub restrict_net_connect: bool,
    /// `true` when bwrap was explicitly requested (`--use-bubblewrap` /
    /// `use_bubblewrap = true`). A spawn-time failure is then a hard error;
    /// on auto-detect it degrades gracefully to Landlock-only.
    pub strict: bool,
}

/// Check if bubblewrap is available on this system.
///
/// Returns the path to the `bwrap` binary if found in PATH. Reuses the
/// project's own PATH resolver so no extra crate is needed.
pub(crate) fn check_availability() -> Option<PathBuf> {
    super::exec::which_binary("bwrap")
}

/// Test that bubblewrap can actually create the namespaces we use.
///
/// Runs `bwrap <production args> /bin/true`. The args come straight from
/// [`build_bwrap_args`] (plus `/bin/true`) so the probe can never drift from
/// the real invocation. Catches hardened hosts where `bwrap` exists but user
/// namespaces are disabled.
pub(crate) fn test_functionality(
    bwrap_path: &Path,
    fs_rules: &[FsRule],
    ro_protect: &[PathBuf],
) -> Result<(), String> {
    let mut args = build_bwrap_args(fs_rules, ro_protect);
    args.push("--".to_string());
    args.push("/bin/true".to_string());

    let output = Command::new(bwrap_path)
        .args(&args)
        .output()
        .map_err(|e| format!("Failed to spawn bwrap test: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bwrap test failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Build the `bwrap` namespace/mount arguments (everything before `-- <cmd>`).
///
/// # Mount strategy
///
/// The goal is for the mount topology inside the namespaces to expose the same
/// inode at each path that the Landlock rule for that path was written for, so
/// the in-namespace Landlock application (the re-entry helper) is faithful:
///
/// 1. `--ro-bind / /` — the whole host filesystem, read-only. This covers
///    every read-only Landlock rule with zero extra arguments.
/// 2. `--proc /proc`, `--dev /dev` — fresh mounts required by the PID / user
///    namespaces. These are managed by bwrap; the helper re-opens the device
///    and `/proc/self` fds *inside* the namespace so Landlock binds to the
///    namespace's nodes, not the host's.
/// 3. `--tmpfs /tmp` — a private, empty `/tmp`. Crucially it is a plain tmpfs,
///    **not** the scratch dir. The scratch dir carries a write+exec Landlock
///    rule; overlaying it on `/tmp` would make all of `/tmp` executable and
///    break the "exec from /tmp is denied" guarantee. Keeping `/tmp` a bare
///    tmpfs preserves that guarantee (its Landlock rule grants no execute).
/// 4. For every **writable** Landlock rule, `--bind <path> <path>` at its real
///    location so writes actually reach the backing store (the read-only base
///    from step 1 would otherwise deny them). Writable paths that live under
///    `/tmp` (e.g. the scratch dir, or a `--project-dir` inside `/tmp`) are
///    bound *after* the `--tmpfs /tmp` so they shadow it and stay visible —
///    fixing the case where a project under `/tmp` vanished inside the sandbox.
///
/// Paths managed by bwrap (`/proc`, `/dev`, `/sys`) and the `/tmp` mount point
/// itself are skipped in step 4 — binding host `/tmp` back over the tmpfs would
/// re-expose host temp files and re-break the exec guarantee.
///
/// 5. Finally, for every path in `ro_protect` that exists, `--ro-bind <p> <p>`
///    is emitted *after* the writable binds so it shadows them read-only. This
///    is the Finding 1 persistence mitigation: the project's `.git/hooks` lives
///    inside the writable project tree, which Landlock cannot carve a sub-deny
///    out of. A read-only bwrap mount restores parity — an agent can no longer
///    plant a hook file that runs unsandboxed on the next `git` invocation. The
///    protected set is deliberately narrow (`.git/hooks`, `.cplt.toml`) — see
///    [`git_persistence_paths`] for why `.git/config`/`.gitmodules` are left
///    writable and for the `core.hooksPath` residual.
///
///    Two documented residuals: a read-only bind only protects paths that
///    already **exist** at launch — bwrap errors on a missing bind source and
///    cannot bind a nonexistent path, so a not-yet-created `.cplt.toml` can
///    still be created by the agent; and submodule hooks
///    (`.git/modules/<name>/hooks`) are not covered. Both are documented in
///    SECURITY.md.
pub(crate) fn build_bwrap_args(fs_rules: &[FsRule], ro_protect: &[PathBuf]) -> Vec<String> {
    let mut args = Vec::new();

    // ── Namespace isolation (network intentionally shared — see module docs) ──
    args.extend([
        "--unshare-pid".to_string(),
        "--unshare-ipc".to_string(),
        "--unshare-uts".to_string(),
        "--unshare-cgroup".to_string(),
        "--unshare-user".to_string(),
        "--die-with-parent".to_string(),
    ]);

    // ── Base filesystem: whole host root, read-only ──
    args.extend(["--ro-bind".to_string(), "/".to_string(), "/".to_string()]);
    args.extend(["--proc".to_string(), "/proc".to_string()]);
    args.extend(["--dev".to_string(), "/dev".to_string()]);
    // Private empty /tmp — deliberately a bare tmpfs (no exec-bearing rule).
    args.extend(["--tmpfs".to_string(), "/tmp".to_string()]);

    // ── Writable overlays, shallowest first so parents are bound before
    //    children (bwrap applies operations in order). ──
    let mut writable: Vec<&FsRule> = fs_rules.iter().filter(|r| r.access.write).collect();
    writable.sort_by_key(|r| r.path.components().count());

    for rule in writable {
        let path = &rule.path;
        // Skip bwrap-managed subtrees and the /tmp mount point itself.
        if path.starts_with("/proc")
            || path.starts_with("/dev")
            || path.starts_with("/sys")
            || path == Path::new("/tmp")
        {
            continue;
        }
        // Landlock silently drops rules for non-existent paths; mirror that so
        // we don't hand bwrap a bind source that does not exist.
        if !path.exists() {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        args.extend(["--bind".to_string(), path_str.clone(), path_str]);
    }

    // ── Read-only overlays for git-persistence paths (Finding 1) ──
    // Emitted last so they shadow the writable project bind above.
    for path in ro_protect {
        // bwrap errors on a non-existent bind source; a read-only bind also
        // cannot protect a path that does not yet exist. Skip missing paths
        // (mirrors the writable-bind handling and keeps the probe from failing).
        if !path.exists() {
            continue;
        }
        let path_str = path.to_string_lossy().into_owned();
        args.extend(["--ro-bind".to_string(), path_str.clone(), path_str]);
    }

    args
}

/// Project-internal paths re-bound **read-only** when Bubblewrap is active, to
/// restore the macOS write-deny parity that Landlock cannot express (they live
/// inside the writable project tree, which Landlock cannot carve a sub-deny out
/// of). Only paths that exist on disk are ultimately bound (see
/// [`build_bwrap_args`]).
///
/// The set is deliberately **narrow** — only paths an agent has no legitimate
/// reason to write *and* that are real persistence vectors:
///
/// - `.git/hooks` — the primary persistence escape. A planted hook runs
///   *unsandboxed* on the next `git` invocation; agents do not normally write
///   here.
/// - `.cplt.toml` — relaxes the next session's sandbox; agents do not normally
///   write it, and any `[propose]` block needs explicit trust approval anyway.
///
/// `.git/config` and `.gitmodules` are **deliberately left writable**: read-only
/// binding them would break common, legitimate in-sandbox git operations
/// (`git config user.email/user.name` identity setup — without it the next
/// `git commit` fails "Please tell me who you are" — plus `git remote add`,
/// `git push -u` upstream tracking, and `git submodule add`, which writes
/// `.gitmodules`). Worse, git rewrites config via a `.git/config.lock` +
/// rename-over-file; a denied write can leave a STALE `.git/config.lock` that
/// blocks the user's *next* out-of-sandbox git. This also matches the git
/// command guard, which explicitly allows `git config user.name`.
///
/// RESIDUAL: because `.git/config` stays writable, an agent can still set
/// `core.hooksPath` to redirect hooks to a writable directory. The read-only
/// `.git/hooks` bind therefore only mitigates the *direct* persistence vector
/// (planting a hook file); it is not a complete closure of git-hook
/// persistence. See SECURITY.md for the full residual discussion.
///
/// # Worktrees
///
/// In a git **worktree**, `<project>/.git` is a *file* (a gitdir pointer), so
/// `<project>/.git/hooks` does not exist and the real hooks live under the
/// shared common dir (`<git_common_dir>/hooks`) — which the sandbox grants
/// write access to. Protecting only the project's `.git/hooks` would therefore
/// miss the actual persistence vector for worktrees. When `git_common_dir` is
/// known (worktree case) and differs from `<project>/.git`, we ALSO protect
/// `<git_common_dir>/hooks`. Non-existent paths are skipped downstream (see
/// [`build_bwrap_args`]).
pub(crate) fn git_persistence_paths(
    project_dir: &Path,
    git_common_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = vec![
        project_dir.join(".git/hooks"),
        project_dir.join(".cplt.toml"),
    ];
    // Worktree: the shared common dir holds the real hooks. `git_common_dir` is
    // only `Some` for a worktree (see `discover::git_common_dir`), but guard on
    // it differing from `<project>/.git` so a regular repo never double-binds.
    if let Some(common) = git_common_dir
        && common != project_dir.join(".git")
    {
        paths.push(common.join("hooks"));
    }
    paths
}

/// Resolve whether bubblewrap should wrap this run, and build the wrapper.
///
/// Single strictness-parameterised path so the `Some(true)` and `None` arms no
/// longer duplicate the availability → probe → build sequence:
/// - `Some(false)` → never wrap.
/// - `Some(true)`  → wrap, or return `Err` (caller bails).
/// - `None`        → wrap if available, else warn and fall back (`Ok(None)`).
///
/// The `fs_rules`/`net_rules` clones happen only on the arms that actually
/// build a wrapper — never on the disabled or fallback paths.
pub(crate) fn resolve(
    use_bubblewrap: Option<bool>,
    fs_rules: &[FsRule],
    net_rules: &[NetRule],
    restrict_net_connect: bool,
    ro_protect: &[PathBuf],
) -> Result<Option<BubblewrapWrapper>, String> {
    match use_bubblewrap {
        Some(false) => Ok(None),
        Some(true) => build_wrapper(fs_rules, net_rules, restrict_net_connect, ro_protect, true)
            .map(Some)
            .map_err(|e| {
                format!(
                    "Bubblewrap explicitly requested but unavailable: {e}. \
                     Install bubblewrap or remove --use-bubblewrap."
                )
            }),
        None => match build_wrapper(fs_rules, net_rules, restrict_net_connect, ro_protect, false) {
            Ok(wrapper) => Ok(Some(wrapper)),
            Err(e) => {
                crate::ui::warn(&format!(
                    "Bubblewrap unavailable ({e}). Using Landlock + seccomp only."
                ));
                Ok(None)
            }
        },
    }
}

fn build_wrapper(
    fs_rules: &[FsRule],
    net_rules: &[NetRule],
    restrict_net_connect: bool,
    ro_protect: &[PathBuf],
    strict: bool,
) -> Result<BubblewrapWrapper, String> {
    let bwrap_path = check_availability().ok_or_else(|| "bwrap not found in PATH".to_string())?;
    test_functionality(&bwrap_path, fs_rules, ro_protect)?;
    let bwrap_args = build_bwrap_args(fs_rules, ro_protect);
    Ok(BubblewrapWrapper {
        bwrap_path,
        bwrap_args,
        fs_rules: fs_rules.to_vec(),
        net_rules: net_rules.to_vec(),
        restrict_net_connect,
        strict,
    })
}

// ── Re-entry helper: policy transfer ───────────────────────────

#[derive(Serialize, Deserialize)]
struct InnerRule {
    path: String,
    r: bool,
    w: bool,
    x: bool,
    i: bool,
}

impl InnerRule {
    fn from_fs_rule(rule: &FsRule) -> Self {
        Self {
            path: rule.path.to_string_lossy().into_owned(),
            r: rule.access.read,
            w: rule.access.write,
            x: rule.access.execute,
            i: rule.access.ioctl,
        }
    }

    fn to_fs_rule(&self) -> FsRule {
        FsRule {
            path: PathBuf::from(&self.path),
            access: FsAccess {
                read: self.r,
                write: self.w,
                execute: self.x,
                ioctl: self.i,
            },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct InnerPolicy {
    fs_rules: Vec<InnerRule>,
    net_ports: Vec<u16>,
    restrict_net_connect: bool,
    /// `[agent_binary, args...]` — `execve`-ed verbatim by the helper.
    agent_argv: Vec<String>,
}

/// Serialize the Landlock policy + agent argv for transfer to the re-entry
/// helper over the policy pipe.
pub(crate) fn serialize_policy(
    wrapper: &BubblewrapWrapper,
    agent_bin: &Path,
    agent_args: &[String],
) -> std::io::Result<Vec<u8>> {
    let mut agent_argv = Vec::with_capacity(agent_args.len() + 1);
    agent_argv.push(agent_bin.to_string_lossy().into_owned());
    agent_argv.extend(agent_args.iter().cloned());

    let policy = InnerPolicy {
        fs_rules: wrapper
            .fs_rules
            .iter()
            .map(InnerRule::from_fs_rule)
            .collect(),
        net_ports: wrapper.net_rules.iter().map(|r| r.port).collect(),
        restrict_net_connect: wrapper.restrict_net_connect,
        agent_argv,
    };
    serde_json::to_vec(&policy).map_err(std::io::Error::other)
}

// ── Re-entry helper: the .init_array constructor ───────────────

/// Constructor that runs before `main()`. Fast no-op on a normal run; only
/// does work when this process is the bwrap-spawned re-entry helper.
///
/// Registered in `.init_array` so no `main.rs` dispatch is needed. Glibc calls
/// entries with `(argc, argv, envp)`; the extra C arguments are harmless to an
/// `extern "C" fn()`.
#[used]
#[unsafe(link_section = ".init_array")]
static BWRAP_INNER_CTOR: extern "C" fn() = bwrap_inner_entry;

extern "C" fn bwrap_inner_entry() {
    if std::env::var_os(ENV_INNER_POLICY).is_none() {
        // Overwhelmingly common case: we are a normal cplt process.
        return;
    }
    run_inner();
    // `run_inner` only returns on failure; on success it `execve`-s the agent.
    // We must NOT fall through to `main()` (it would run partially sandboxed).
    // Exiting without writing the confirm byte tells the parent to fall back
    // (auto-detect) or report a hard error (explicit --use-bubblewrap).
    unsafe { libc::_exit(126) };
}

/// Apply the inner sandbox from the serialized policy, then `execve` the agent.
///
/// Returns only on failure (so the caller can `_exit`). Security-critical:
/// this is the process that becomes the agent, so Landlock + seccomp MUST be
/// enforced here before `execve`.
fn run_inner() {
    let Some(fd) = std::env::var_os(ENV_INNER_POLICY)
        .and_then(|v| v.to_str().and_then(|s| s.parse::<i32>().ok()))
    else {
        return;
    };
    let Some(data) = read_all_fd(fd) else {
        return;
    };
    let Ok(policy) = serde_json::from_slice::<InnerPolicy>(&data) else {
        return;
    };

    let fs_rules: Vec<FsRule> = policy.fs_rules.iter().map(InnerRule::to_fs_rule).collect();
    let net_rules: Vec<NetRule> = policy
        .net_ports
        .iter()
        .map(|&port| NetRule { port })
        .collect();

    // Bind Landlock to in-namespace inodes and install seccomp. If this fails
    // we return without signalling success — never run the agent unsandboxed.
    if crate::sandbox::landlock_mod::apply_landlock_and_seccomp_now(
        &fs_rules,
        &net_rules,
        policy.restrict_net_connect,
    )
    .is_err()
    {
        return;
    }

    // Signal the parent that the sandbox is in force, then close the pipe so it
    // does not leak into the agent.
    if let Some(fd) = std::env::var_os(ENV_CONFIRM_FD)
        .and_then(|v| v.to_str().and_then(|s| s.parse::<i32>().ok()))
    {
        let byte = [1u8];
        unsafe {
            libc::write(fd, byte.as_ptr().cast(), 1);
            libc::close(fd);
        }
    }

    // Scrub our private env before handing off to the agent.
    scrub_env(ENV_INNER_POLICY);
    scrub_env(ENV_CONFIRM_FD);

    exec_agent(&policy.agent_argv);
    // `exec_agent` only returns if `execve` failed.
}

/// Read the whole policy pipe until EOF, then close the fd.
///
/// Runs pre-`main()` in the freshly exec'd helper — single-threaded, so plain
/// blocking reads and allocation are fine. Returns `None` on any read error.
fn read_all_fd(fd: i32) -> Option<Vec<u8>> {
    let mut data = Vec::with_capacity(16 * 1024);
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return None;
        }
        if n == 0 {
            break;
        }
        #[allow(clippy::cast_sign_loss)]
        data.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(fd) };
    Some(data)
}

fn scrub_env(name: &str) {
    if let Ok(cname) = CString::new(name) {
        unsafe {
            libc::unsetenv(cname.as_ptr());
        }
    }
}

/// `execve` the agent, inheriting the current (namespace) environment.
fn exec_agent(argv: &[String]) {
    let Some(bin) = argv.first() else {
        return;
    };
    let Ok(path) = CString::new(bin.as_bytes()) else {
        return;
    };
    let mut cargs: Vec<CString> = Vec::with_capacity(argv.len());
    for arg in argv {
        let Ok(c) = CString::new(arg.as_bytes()) else {
            return;
        };
        cargs.push(c);
    }
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe {
        libc::execv(path.as_ptr(), ptrs.as_ptr());
    }
    // Only reached if execv failed.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn writable_rule(path: &str) -> FsRule {
        FsRule {
            path: PathBuf::from(path),
            access: FsAccess {
                read: true,
                write: true,
                execute: true,
                ioctl: false,
            },
        }
    }

    #[test]
    fn args_isolate_expected_namespaces() {
        let args = build_bwrap_args(&[], &[]);
        assert!(args.contains(&"--unshare-pid".to_string()));
        assert!(args.contains(&"--unshare-ipc".to_string()));
        assert!(args.contains(&"--unshare-uts".to_string()));
        assert!(args.contains(&"--unshare-cgroup".to_string()));
        assert!(args.contains(&"--unshare-user".to_string()));
        assert!(args.contains(&"--die-with-parent".to_string()));
        // Network namespace is intentionally shared (proxy runs on the host).
        assert!(!args.contains(&"--unshare-net".to_string()));
    }

    #[test]
    fn args_set_up_base_mounts() {
        let args = build_bwrap_args(&[], &[]);
        assert!(args.windows(3).any(|w| w == ["--ro-bind", "/", "/"]));
        assert!(args.windows(2).any(|w| w == ["--proc", "/proc"]));
        assert!(args.windows(2).any(|w| w == ["--dev", "/dev"]));
        // /tmp is a bare tmpfs, never the scratch dir (exec-from-/tmp guarantee).
        assert!(args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]));
    }

    #[test]
    fn tmp_is_never_bind_mounted_from_host() {
        // A writable /tmp rule must NOT re-bind host /tmp over the tmpfs, which
        // would re-expose host temp files and grant exec through /tmp.
        let rules = vec![FsRule {
            path: PathBuf::from("/tmp"),
            access: FsAccess {
                read: true,
                write: true,
                execute: false,
                ioctl: false,
            },
        }];
        let args = build_bwrap_args(&rules, &[]);
        let tmp_bind = args
            .windows(3)
            .any(|w| w[0] == "--bind" && w[1] == "/tmp" && w[2] == "/tmp");
        assert!(!tmp_bind, "/tmp must stay a private tmpfs, not a host bind");
    }

    #[test]
    fn writable_paths_under_tmp_survive_the_tmp_shadow() {
        // Regression: a scratch dir or --project-dir under /tmp must survive
        // the --tmpfs /tmp shadow via an explicit writable bind emitted AFTER
        // the tmpfs (bwrap applies mount operations in argument order).
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_str = dir.path().to_string_lossy().into_owned();
        assert!(
            dir.path().starts_with(std::env::temp_dir()),
            "test premise: tempdir lives under the system temp dir"
        );
        let rules = vec![writable_rule(&dir_str)];
        let args = build_bwrap_args(&rules, &[]);

        let tmpfs_idx = args.iter().position(|a| a == "--tmpfs").expect("tmpfs");
        let bind_idx = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == dir_str && w[2] == dir_str)
            .expect("writable path under /tmp must be bound (project-under-/tmp regression)");
        assert!(
            bind_idx > tmpfs_idx,
            "writable bind under /tmp must come after --tmpfs /tmp to shadow it"
        );
    }

    #[test]
    fn nothing_shadows_tmp_mount_point() {
        // SECURITY (exec-from-/tmp guarantee): /tmp inside the namespace must
        // be the bare tmpfs — in particular the scratch dir (whose Landlock
        // rule always grants write+exec) must never be mounted AT /tmp. If it
        // were, files created via /tmp would carry the scratch rule's exec
        // right and `cp payload /tmp/x && /tmp/x` would run, which every
        // non-bwrap configuration kernel-denies by default.
        let dir = tempfile::tempdir().expect("tempdir");
        let scratch_like = writable_rule(&dir.path().to_string_lossy());
        let args = build_bwrap_args(&[scratch_like], &[]);

        // No mount operation may target /tmp as its destination other than the
        // tmpfs itself.
        let tmp_dest = args
            .windows(3)
            .any(|w| (w[0] == "--bind" || w[0] == "--ro-bind") && w[2] == "/tmp");
        assert!(!tmp_dest, "no bind may target the /tmp mount point");
        assert!(args.windows(2).any(|w| w == ["--tmpfs", "/tmp"]));
    }

    #[test]
    fn nonexistent_writable_paths_are_skipped() {
        let rules = vec![writable_rule("/definitely/not/a/real/path/xyzzy")];
        let args = build_bwrap_args(&rules, &[]);
        assert!(!args.iter().any(|a| a.contains("xyzzy")));
    }

    #[test]
    fn bwrap_managed_subtrees_are_not_rebound() {
        let rules = vec![
            writable_rule("/dev/tty"),
            writable_rule("/proc/self"),
            writable_rule("/sys/fs/cgroup"),
        ];
        let args = build_bwrap_args(&rules, &[]);
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--bind" && w[1] == "/dev/tty")
        );
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--bind" && w[1] == "/proc/self")
        );
        assert!(
            !args
                .windows(3)
                .any(|w| w[0] == "--bind" && w[1] == "/sys/fs/cgroup")
        );
    }

    #[test]
    fn resolve_disabled_returns_none() {
        assert!(resolve(Some(false), &[], &[], true, &[]).unwrap().is_none());
    }

    #[test]
    fn git_hooks_are_rebound_read_only_after_writable_project() {
        // Finding 1: an existing project/.git/hooks inside the writable project
        // tree must be re-bound read-only, and AFTER the writable project bind so
        // the read-only mount shadows it (bwrap applies mounts in argument order).
        let proj = tempfile::tempdir().expect("tempdir");
        let hooks = proj.path().join(".git/hooks");
        std::fs::create_dir_all(&hooks).expect("create .git/hooks");
        let proj_str = proj.path().to_string_lossy().into_owned();
        let hooks_str = hooks.to_string_lossy().into_owned();

        let rules = vec![writable_rule(&proj_str)];
        let ro = git_persistence_paths(proj.path(), None);
        let args = build_bwrap_args(&rules, &ro);

        let proj_bind_idx = args
            .windows(3)
            .position(|w| w[0] == "--bind" && w[1] == proj_str && w[2] == proj_str)
            .expect("writable project must be bound");
        let hooks_ro_idx = args
            .windows(3)
            .position(|w| w[0] == "--ro-bind" && w[1] == hooks_str && w[2] == hooks_str)
            .expect(".git/hooks must be re-bound read-only");
        assert!(
            hooks_ro_idx > proj_bind_idx,
            "read-only .git/hooks bind must come AFTER the writable project bind"
        );
    }

    #[test]
    fn ro_protect_set_is_narrow_and_leaves_git_config_writable() {
        // The protected set is deliberately narrow: only .git/hooks and
        // .cplt.toml. .git/config / .gitmodules must stay writable so legit
        // in-sandbox git config/remote/submodule ops (and their lock files)
        // are not broken — even when those files exist on disk.
        let proj = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(proj.path().join(".git/hooks")).expect("create .git/hooks");
        std::fs::write(proj.path().join(".git/config"), "").expect("create .git/config");
        std::fs::write(proj.path().join(".gitmodules"), "").expect("create .gitmodules");
        std::fs::write(proj.path().join(".cplt.toml"), "").expect("create .cplt.toml");

        let proj_str = proj.path().to_string_lossy().into_owned();
        let rules = vec![writable_rule(&proj_str)];
        let ro = git_persistence_paths(proj.path(), None);
        let args = build_bwrap_args(&rules, &ro);

        // .git/hooks and .cplt.toml are re-bound read-only.
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--ro-bind"
                    && w[1] == proj.path().join(".git/hooks").to_string_lossy()),
            ".git/hooks must be re-bound read-only"
        );
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--ro-bind"
                    && w[1] == proj.path().join(".cplt.toml").to_string_lossy()),
            ".cplt.toml must be re-bound read-only"
        );
        // .git/config and .gitmodules are NOT re-bound (stay writable), even
        // though both exist on disk — the narrowing, not the exists-check, is
        // what leaves them out.
        assert!(
            !args.iter().any(|a| a.ends_with("/.git/config")),
            ".git/config must NOT be re-bound read-only (would break git config/remote ops)"
        );
        assert!(
            !args.iter().any(|a| a.ends_with("/.gitmodules")),
            ".gitmodules must NOT be re-bound read-only (would break git submodule add)"
        );
    }

    #[test]
    fn nonexistent_git_persistence_paths_are_skipped() {
        // A read-only bind of a missing path would make bwrap error (failing the
        // probe) and cannot protect a not-yet-created file anyway — skip it.
        let proj = tempfile::tempdir().expect("tempdir");
        // No .git/hooks or .cplt.toml created.
        let ro = git_persistence_paths(proj.path(), None);
        let args = build_bwrap_args(&[], &ro);
        assert!(
            !args
                .iter()
                .any(|a| a.contains(".git/hooks") || a.contains(".cplt.toml")),
            "missing git-persistence paths must not be bound"
        );
    }

    #[test]
    fn worktree_common_dir_hooks_are_protected() {
        // In a git worktree, <project>/.git is a FILE pointing at the shared
        // gitdir, so <project>/.git/hooks does not exist and the real hooks live
        // under git_common_dir/hooks (which the sandbox grants write access to).
        // The ro_protect set MUST include the common-dir hooks so the
        // persistence-escape mitigation does not miss them.
        let common = tempfile::tempdir().expect("tempdir"); // shared .git dir
        let common_hooks = common.path().join("hooks");
        std::fs::create_dir_all(&common_hooks).expect("create common hooks");

        let proj = tempfile::tempdir().expect("tempdir"); // worktree checkout
        let ro = git_persistence_paths(proj.path(), Some(common.path()));

        assert!(
            ro.contains(&common_hooks),
            "worktree common-dir hooks must be in the ro_protect set"
        );

        // And once bound they are re-bound read-only (they exist on disk).
        let args = build_bwrap_args(&[], &ro);
        let common_hooks_str = common_hooks.to_string_lossy().into_owned();
        assert!(
            args.windows(3).any(|w| w[0] == "--ro-bind"
                && w[1] == common_hooks_str
                && w[2] == common_hooks_str),
            "worktree common-dir hooks must be re-bound read-only"
        );
    }

    #[test]
    fn regular_repo_does_not_double_bind_git_dir() {
        // Defensive guard: if git_common_dir were ever `Some(<project>/.git)`
        // (a non-worktree), it must NOT be added a second time — the standard
        // <project>/.git/hooks entry already covers it.
        let proj = tempfile::tempdir().expect("tempdir");
        let ro = git_persistence_paths(proj.path(), Some(&proj.path().join(".git")));
        let hooks = proj.path().join(".git/hooks");
        assert_eq!(
            ro.iter().filter(|p| **p == hooks).count(),
            1,
            "the project's .git/hooks must appear exactly once"
        );
    }
}
