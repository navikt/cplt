//! `cplt check` — verify & explain sandbox enforcement.
//!
//! Two layers, matching the PRD (#142):
//!
//! 1. **Enforcement probes** (Layer 1) execute inside the *real* resolved
//!    sandbox / against the resolved proxy policy and report ground truth:
//!    a path is genuinely readable or the kernel denies it, a domain is
//!    genuinely permitted by the proxy or refused. Those probes live in the
//!    binary (`main.rs`), which owns the sandbox plumbing; they feed their
//!    results into the [`CheckItem`] / [`Report`] types defined here.
//!
//! 2. **Explain + fix** (Layer 2) is the pure policy-query API in this module:
//!    [`explain_path`], [`explain_domain`], and [`explain_exec`]. Each maps a
//!    result to *why* (which rule / status governs it) and *how to change it*
//!    (the exact config key / flag / preset). These reuse the existing matchers
//!    — the Landlock `fs_rules` model, [`crate::proxy::classify_connect`], and
//!    the gh/git guard classifiers — rather than duplicating them.
//!
//! # Honest scope
//!
//! Probes reflect cplt's *resolved policy*: what cplt itself grants or blocks.
//! A passing network probe means "cplt is not blocking this" — not that the
//! target is up or that an arbitrary agent action with a different cwd/env would
//! behave identically. The static `fs_rules` model is a faithful approximation
//! of the enforced filesystem policy; where the live probe disagrees (e.g. a
//! macOS SBPL deny-subpath the Landlock model can't express) the *probe* is
//! authoritative and the explanation notes the difference.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::proxy::{self, NetPolicy, NetVerdict};
use crate::sandbox::{
    DENIED_DOTFILES, DENIED_FILES, DENIED_HOME_SUBPATHS, FsAccess, LandlockPolicy,
};

/// Ground-truth (or, for static-only queries, policy) decision for one probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// cplt permits the operation.
    Allowed,
    /// cplt blocks the operation.
    Blocked,
    /// The probe could not be run to a conclusive result (e.g. the target does
    /// not exist, or a probe prerequisite failed). Never counts as a verified
    /// protection and never fails the enforcement verdict.
    Inconclusive,
}

impl Decision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allowed => "ALLOWED",
            Decision::Blocked => "BLOCKED",
            Decision::Inconclusive => "INCONCLUSIVE",
        }
    }
}

// ── Layer 2: filesystem explain ────────────────────────────────

/// Static explanation of a path against the resolved filesystem policy.
#[derive(Debug, Clone, Serialize)]
pub struct FsExplain {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    /// The longest matching allow rule (most specific ancestor), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    /// Whether the path is a known protected credential location.
    pub credential: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl FsExplain {
    /// The decision the static model predicts for a *read* of this path.
    #[must_use]
    pub fn read_decision(&self) -> Decision {
        if self.read {
            Decision::Allowed
        } else {
            Decision::Blocked
        }
    }

    /// The decision the static model predicts for a *write* to this path.
    #[must_use]
    pub fn write_decision(&self) -> Decision {
        if self.write {
            Decision::Allowed
        } else {
            Decision::Blocked
        }
    }
}

/// Render `{read,write,execute}` as a compact `read+write+execute` string.
fn access_str(a: &FsAccess) -> String {
    let mut parts = Vec::new();
    if a.read {
        parts.push("read");
    }
    if a.write {
        parts.push("write");
    }
    if a.execute {
        parts.push("execute");
    }
    if parts.is_empty() {
        "no access".to_string()
    } else {
        parts.join("+")
    }
}

/// Is `path` equal to, or nested under, `base` (component-wise)?
fn within(path: &Path, base: &Path) -> bool {
    path == base || path.starts_with(base)
}

/// Whether `path` is a known protected credential location under `home`.
///
/// Reuses the sandbox's own deny lists (`DENIED_DOTFILES`, `DENIED_FILES`,
/// `DENIED_HOME_SUBPATHS`) so the classification never drifts from what the
/// profile actually withholds.
#[must_use]
pub fn is_credential_path(home: &Path, path: &Path) -> bool {
    for d in DENIED_DOTFILES {
        if within(path, &home.join(d)) {
            return true;
        }
    }
    for f in DENIED_FILES {
        if within(path, &home.join(f)) {
            return true;
        }
    }
    for f in DENIED_HOME_SUBPATHS {
        if within(path, &home.join(f)) {
            return true;
        }
    }
    false
}

/// Explain a path against the resolved filesystem policy (longest-prefix match).
///
/// Landlock grants are additive over a path's ancestors, so the effective access
/// is the union of every rule whose path is an ancestor-or-equal of `path`; the
/// most specific such rule is reported as the matched rule. The reason→fix text
/// is drawn from a small catalog focused on the high-frequency cases
/// (credentials, the project dir) with a sensible generic fallback.
#[must_use]
pub fn explain_path(
    policy: &LandlockPolicy,
    home: &Path,
    project_dir: &Path,
    path: &Path,
) -> FsExplain {
    let mut acc = FsAccess::default();
    let mut matched: Option<&PathBuf> = None;
    for rule in &policy.fs_rules {
        if within(path, &rule.path) {
            acc.read |= rule.access.read;
            acc.write |= rule.access.write;
            acc.execute |= rule.access.execute;
            let longer = matched.is_none_or(|m| rule.path.as_os_str().len() > m.as_os_str().len());
            if longer {
                matched = Some(&rule.path);
            }
        }
    }

    let credential = is_credential_path(home, path);
    let matched_str = matched.map(|p| p.display().to_string());

    let (reason, fix) = if credential && !acc.read {
        (
            "protected credential path — never exposed to the agent (deny-by-default). \
             This is intentional."
                .to_string(),
            None,
        )
    } else if credential && acc.read {
        (
            "credential path, but read was explicitly granted for this run \
             (allow.read / --allow-read)."
                .to_string(),
            Some(
                "remove the matching allow.read entry / --allow-read flag to re-protect it."
                    .to_string(),
            ),
        )
    } else if within(path, project_dir) {
        (
            format!("covered by the project-dir rule ({}).", access_str(&acc)),
            None,
        )
    } else if acc.read || acc.write || acc.execute {
        (
            format!(
                "granted {} by rule {}.",
                access_str(&acc),
                matched_str.as_deref().unwrap_or("(project dir)")
            ),
            None,
        )
    } else {
        (
            "not covered by any allow rule — denied by default.".to_string(),
            Some(
                "grant access with --allow-read <PATH> (read) or --allow-write <PATH> (read+write), \
                 or add it under [allow] read/write in config."
                    .to_string(),
            ),
        )
    };

    FsExplain {
        read: acc.read,
        write: acc.write,
        execute: acc.execute,
        matched_rule: matched_str,
        credential,
        reason,
        fix,
    }
}

// ── Layer 2: network explain ───────────────────────────────────

/// Static explanation of a CONNECT target against the resolved proxy policy.
#[derive(Debug, Clone, Serialize)]
pub struct NetExplain {
    pub decision: Decision,
    /// The proxy audit-log status (`ALLOWED`, `BLOCKED-PRIVATE`, `NO-PROXY`, …).
    pub status: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// Explain a domain/port against the resolved proxy policy.
///
/// When the proxy is disabled cplt does no domain filtering at all, so this is
/// reported honestly (`NO-PROXY`) rather than implying a block. Otherwise the
/// verdict comes straight from [`crate::proxy::classify_connect`] — the same
/// gate logic the live proxy enforces — and each `BLOCKED-*` status is mapped to
/// the governing config plus the exact fix.
#[must_use]
pub fn explain_domain(
    policy: &NetPolicy,
    host: &str,
    port: u16,
    proxy_enabled: bool,
) -> NetExplain {
    if !proxy_enabled {
        return NetExplain {
            decision: Decision::Allowed,
            status: "NO-PROXY".to_string(),
            reason: "the CONNECT proxy is disabled, so cplt does not filter domains; \
                     egress is constrained only by the kernel port policy (443 + --allow-port)."
                .to_string(),
            fix: Some(
                "enable domain filtering with --with-proxy, or lock egress down with --preset strict."
                    .to_string(),
            ),
        };
    }

    let verdict = proxy::classify_connect(policy, host, port);
    let (decision, reason, fix) = match verdict {
        NetVerdict::Allowed => (
            Decision::Allowed,
            "permitted by the proxy policy — cplt is not blocking this.".to_string(),
            None,
        ),
        NetVerdict::BlockedPort => (
            Decision::Blocked,
            format!("port {port} is not in the allowed-ports set (443 + --allow-port)."),
            Some(format!(
                "allow it with --allow-port {port} (or [allow] ports in config)."
            )),
        ),
        NetVerdict::BlockedAllowlist => (
            Decision::Blocked,
            "a fail-closed domain allowlist is active and this host is not in it \
             (agent defaults + your allowed_domains)."
                .to_string(),
            Some(
                "add it to allowed_domains (--allowed-domains FILE / [proxy] allowed_domains), \
                 or run with --allow-all-domains."
                    .to_string(),
            ),
        ),
        NetVerdict::Blocked => (
            Decision::Blocked,
            "the host matches the proxy blocklist (blocked-domains).".to_string(),
            Some(
                "if you trust it, remove it from the blocklist file (--blocked-domains)."
                    .to_string(),
            ),
        ),
        NetVerdict::BlockedPrivate => (
            Decision::Blocked,
            "private / loopback / link-local target — blocked as an SSRF safeguard \
             (e.g. cloud metadata 169.254.169.254, internal services)."
                .to_string(),
            Some(
                "for a trusted internal host use --allow-private-domains <DOMAIN>; \
                 for a local dev server use --allow-localhost <PORT>."
                    .to_string(),
            ),
        ),
    };

    NetExplain {
        decision,
        status: verdict.status().to_string(),
        reason,
        fix,
    }
}

// ── Layer 2: exec explain ──────────────────────────────────────

/// The exec-relevant slice of the resolved policy, for [`explain_exec`].
pub struct ExecContext<'a> {
    pub allow_docker: bool,
    pub allow_tmp_exec: bool,
    pub gh_guard: &'a crate::config::GhGuardPolicy,
    pub git_guard: &'a crate::config::GitGuardPolicy,
    pub project_dir: &'a Path,
}

/// Static explanation of whether a command would run under the resolved policy.
#[derive(Debug, Clone, Serialize)]
pub struct ExecExplain {
    pub decision: Decision,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

/// The file-name (last component) of a command word, lowercased.
fn command_basename(cmd: &str) -> String {
    Path::new(cmd)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// Explain whether `argv` would run, is guard-blocked, or needs an `allow_*`.
///
/// Reuses the gh/git guard classifiers ([`crate::gh_proxy::gate`],
/// [`crate::gh_proxy::gate_git`]) so the verdict matches what the in-sandbox
/// wrappers enforce, and the `allow_docker` / `allow_tmp_exec` gates for the
/// other high-frequency cases. Unrecognized commands get an honest generic
/// answer (they run, subject to the fs/net policy).
#[must_use]
pub fn explain_exec(argv: &[String], ctx: &ExecContext) -> ExecExplain {
    let Some(first) = argv.first() else {
        return ExecExplain {
            decision: Decision::Inconclusive,
            reason: "no command given.".to_string(),
            fix: None,
        };
    };
    let base = command_basename(first);
    let rest: Vec<&str> = argv[1..].iter().map(String::as_str).collect();

    // ── Docker family: gated by allow_docker (socket = host RCE) ──
    if matches!(
        base.as_str(),
        "docker" | "docker-compose" | "colima" | "nerdctl"
    ) {
        return if ctx.allow_docker {
            ExecExplain {
                decision: Decision::Allowed,
                reason: "Docker access is enabled (allow_docker=on).".to_string(),
                fix: None,
            }
        } else {
            ExecExplain {
                decision: Decision::Blocked,
                reason: "Docker access is gated off — the daemon socket and ~/.docker are denied \
                         (allow_docker=off). It is dangerous: socket access is effectively host RCE \
                         and volume mounts bypass the sandbox filesystem."
                    .to_string(),
                fix: Some(
                    "--allow-docker, or [sandbox] allow_docker = true (or --preset full-trust)."
                        .to_string(),
                ),
            }
        };
    }

    // ── git: push-prevention guard ──
    if base == "git" {
        if !ctx.git_guard.enabled {
            return ExecExplain {
                decision: Decision::Allowed,
                reason: "git runs; push prevention is not enabled for this run.".to_string(),
                fix: None,
            };
        }
        return match crate::gh_proxy::gate_git(
            &rest,
            ctx.git_guard.prevent_push,
            ctx.git_guard.prevent_force_push,
            ctx.git_guard.protect_default_branch_only,
            &ctx.git_guard.allow_push,
            None,
        ) {
            Ok(()) => ExecExplain {
                decision: Decision::Allowed,
                reason: "allowed by the git guard.".to_string(),
                fix: None,
            },
            Err(msg) => ExecExplain {
                decision: Decision::Blocked,
                reason: first_line(&msg),
                fix: Some(
                    "push to an allowed branch/remote, configure [git] allow_push, \
                     or disable with git_push_prevention = false."
                        .to_string(),
                ),
            },
        };
    }

    // ── gh: destructive-operation guard ──
    if base == "gh" {
        if !ctx.gh_guard.enabled {
            return ExecExplain {
                decision: Decision::Allowed,
                reason: "gh runs; the gh guard is not enabled for this run.".to_string(),
                fix: None,
            };
        }
        let policy = crate::gh_proxy::GatePolicy {
            mode: ctx.gh_guard.mode,
            scope_check: ctx.gh_guard.scope_check,
            block_auth_token: ctx.gh_guard.block_auth_token,
            unknown_command: match ctx.gh_guard.unknown_command {
                crate::config::UnknownCommandPolicy::Allow => {
                    crate::gh_proxy::UnknownCommandDecision::Allow
                }
                crate::config::UnknownCommandPolicy::Block => {
                    crate::gh_proxy::UnknownCommandDecision::Block
                }
            },
            allow_api_write: ctx.gh_guard.allow_api_write,
        };
        return match crate::gh_proxy::gate(&rest, ctx.project_dir, &policy) {
            Ok(()) => ExecExplain {
                decision: Decision::Allowed,
                reason: "allowed by the gh guard.".to_string(),
                fix: None,
            },
            Err(msg) => ExecExplain {
                decision: Decision::Blocked,
                reason: first_line(&msg),
                fix: Some(
                    "use a read-only / in-scope gh command, or relax the gh guard \
                     (e.g. [sandbox] gh_proxy settings)."
                        .to_string(),
                ),
            },
        };
    }

    // ── tmp/scratch exec: binary-drop prevention ──
    if !ctx.allow_tmp_exec && looks_like_tmp_path(first) {
        return ExecExplain {
            decision: Decision::Blocked,
            reason: "executing a binary from /tmp or the scratch dir is blocked \
                     (binary-drop prevention: writable-but-non-executable)."
                .to_string(),
            fix: Some(
                "--allow-tmp-exec, or [sandbox] allow_tmp_exec = true (dangerous).".to_string(),
            ),
        };
    }

    ExecExplain {
        decision: Decision::Allowed,
        reason: "not specifically gated — runs inside the sandbox, subject to the \
                 filesystem, network, and env policy."
            .to_string(),
        fix: None,
    }
}

fn looks_like_tmp_path(cmd: &str) -> bool {
    cmd.starts_with("/tmp/") || cmd.starts_with("/private/tmp/") || cmd.starts_with("/var/tmp/")
}

fn first_line(s: &str) -> String {
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or(s)
        .trim()
        .to_string()
}

// ── Report assembly & rendering ────────────────────────────────

/// One line item in a check report — a single probe or explained query.
#[derive(Debug, Clone, Serialize)]
pub struct CheckItem {
    /// Short human label, e.g. "read project dir".
    pub name: String,
    /// "filesystem" | "network" | "exec".
    pub category: String,
    /// The concrete target (path, `host:port`, or command).
    pub target: String,
    /// Ground-truth (probe) or policy (static) decision.
    pub decision: Decision,
    /// For the enforcement battery: what a working sandbox is expected to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<Decision>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
    /// Extra context (reachability, model-vs-probe mismatch, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl CheckItem {
    /// Did this item meet its expectation? `None` expectation ⇒ not graded.
    #[must_use]
    pub fn passed(&self) -> Option<bool> {
        self.expected.map(|e| e == self.decision)
    }
}

/// A full `cplt check` report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub agent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    pub platform: String,
    /// Whether every graded expectation held (⇒ the sandbox is enforcing).
    pub enforcing: bool,
    /// Number of expected-BLOCKED protections that were actually blocked.
    pub verified: usize,
    /// True for the bare enforcement battery (drives the verdict rendering).
    pub battery: bool,
    pub items: Vec<CheckItem>,
}

impl Report {
    /// Build a report from graded items, computing the enforcement verdict.
    #[must_use]
    pub fn new(
        agent: String,
        preset: Option<String>,
        battery: bool,
        items: Vec<CheckItem>,
    ) -> Self {
        let verified = items
            .iter()
            .filter(|i| i.expected == Some(Decision::Blocked) && i.decision == Decision::Blocked)
            .count();
        // Enforcing iff every graded expectation held AND at least one protection
        // (an expected block) was verified. Inconclusive items are never graded,
        // so they neither verify nor break the verdict.
        let all_graded_passed = items.iter().all(|i| i.passed() != Some(false));
        let enforcing = battery && all_graded_passed && verified >= 1;
        Report {
            agent,
            preset,
            platform: platform_name().to_string(),
            enforcing,
            verified,
            battery,
            items,
        }
    }

    /// Serialize the report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// The process exit code: 0 when enforcing (or a targeted, non-battery
    /// query), non-zero when the battery could not confirm enforcement.
    #[must_use]
    pub fn exit_nonzero(&self) -> bool {
        self.battery && !self.enforcing
    }

    /// Render a clean human-readable report.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();

        if self.battery {
            self.render_battery(&mut out);
        } else {
            for item in &self.items {
                render_targeted_item(&mut out, item);
            }
        }

        // Verdict line (battery only).
        if self.battery {
            let _ = writeln!(out);
            let mut suffix = format!("agent={}", self.agent);
            if let Some(p) = &self.preset {
                let _ = write!(suffix, " · preset={p}");
            }
            if self.enforcing {
                let _ = writeln!(
                    out,
                    "→ Sandbox is ENFORCING ({} protection{} verified) · {}",
                    self.verified,
                    if self.verified == 1 { "" } else { "s" },
                    suffix
                );
            } else {
                let _ = writeln!(
                    out,
                    "→ Sandbox is NOT ENFORCING — {} · {}",
                    self.failure_summary(),
                    suffix
                );
            }
        }
        out
    }

    fn render_battery(&self, out: &mut String) {
        use std::fmt::Write as _;
        for cat in ["filesystem", "network", "exec"] {
            let items: Vec<&CheckItem> = self.items.iter().filter(|i| i.category == cat).collect();
            if items.is_empty() {
                continue;
            }
            let _ = writeln!(out, "{}", cat_title(cat));
            for item in items {
                let sym = match item.passed() {
                    Some(true) => "✓",
                    Some(false) => "✗",
                    None => "·",
                };
                let mut line = format!("  {sym} {:<26} → {}", item.name, item.decision.as_str());
                if item.passed() == Some(false)
                    && let Some(exp) = item.expected
                {
                    let _ = write!(line, "  [expected {}]", exp.as_str());
                }
                if item.decision == Decision::Inconclusive
                    && let Some(note) = &item.note
                {
                    let _ = write!(line, "  ({note})");
                }
                let _ = writeln!(out, "{line}");
            }
        }
    }

    fn failure_summary(&self) -> String {
        let mut reasons = Vec::new();
        let under = self
            .items
            .iter()
            .filter(|i| i.expected == Some(Decision::Blocked) && i.decision == Decision::Allowed)
            .count();
        let over = self
            .items
            .iter()
            .filter(|i| i.expected == Some(Decision::Allowed) && i.decision == Decision::Blocked)
            .count();
        if under > 0 {
            reasons.push(format!("{under} protection(s) did NOT block"));
        }
        if over > 0 {
            reasons.push(format!("{over} expected-allowed check(s) were blocked"));
        }
        if self.verified == 0 && reasons.is_empty() {
            reasons.push("no protection could be verified".to_string());
        }
        reasons.join("; ")
    }
}

fn render_targeted_item(out: &mut String, item: &CheckItem) {
    use std::fmt::Write as _;
    let _ = writeln!(out, "{}: {}", item.target, item.decision.as_str());
    let _ = writeln!(out, "  Reason: {}", item.reason);
    if let Some(note) = &item.note {
        let _ = writeln!(out, "  Note: {note}");
    }
    match &item.fix {
        Some(fix) => {
            let _ = writeln!(out, "  Fix: {fix}");
        }
        None => {
            let _ = writeln!(out, "  Fix: none needed (intentional).");
        }
    }
}

fn cat_title(cat: &str) -> &'static str {
    match cat {
        "filesystem" => "Filesystem",
        "network" => "Network",
        "exec" => "Exec",
        _ => "Other",
    }
}

#[must_use]
fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos (Seatbelt)"
    } else if cfg!(target_os = "linux") {
        "linux (Landlock+seccomp)"
    } else {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GhGuardPolicy, GitGuardPolicy};
    use crate::sandbox::{FsAccess, FsRule, LandlockPolicy};

    fn rule(path: &str, read: bool, write: bool, execute: bool) -> FsRule {
        FsRule {
            path: PathBuf::from(path),
            access: FsAccess {
                read,
                write,
                execute,
                ioctl: false,
            },
        }
    }

    fn policy(rules: Vec<FsRule>) -> LandlockPolicy {
        LandlockPolicy {
            fs_rules: rules,
            net_rules: Vec::new(),
            restrict_net_connect: true,
            proxy_forced: false,
            home_dir: PathBuf::from("/home/u"),
        }
    }

    // ── explain_path ──

    #[test]
    fn project_dir_is_read_write() {
        let home = Path::new("/home/u");
        let proj = Path::new("/home/u/proj");
        let p = policy(vec![rule("/home/u/proj", true, true, true)]);
        let e = explain_path(&p, home, proj, Path::new("/home/u/proj/build/out"));
        assert_eq!(e.read_decision(), Decision::Allowed);
        assert_eq!(e.write_decision(), Decision::Allowed);
        assert!(e.reason.contains("project-dir"));
        assert!(e.fix.is_none());
    }

    #[test]
    fn ssh_key_is_blocked_credential() {
        let home = Path::new("/home/u");
        let proj = Path::new("/home/u/proj");
        // No rule grants ~/.ssh — deny by default.
        let p = policy(vec![rule("/home/u/proj", true, true, true)]);
        let e = explain_path(&p, home, proj, Path::new("/home/u/.ssh/id_rsa"));
        assert_eq!(e.read_decision(), Decision::Blocked);
        assert!(e.credential);
        assert!(e.reason.contains("credential"));
        // Intentional — no fix recommended.
        assert!(e.fix.is_none());
    }

    #[test]
    fn aws_dir_is_credential() {
        let home = Path::new("/home/u");
        assert!(is_credential_path(
            home,
            Path::new("/home/u/.aws/credentials")
        ));
        assert!(is_credential_path(home, Path::new("/home/u/.ssh")));
        assert!(is_credential_path(home, Path::new("/home/u/.netrc")));
        assert!(!is_credential_path(home, Path::new("/home/u/proj/src")));
    }

    #[test]
    fn unlisted_path_is_blocked_with_fix() {
        let home = Path::new("/home/u");
        let proj = Path::new("/home/u/proj");
        let p = policy(vec![rule("/home/u/proj", true, true, true)]);
        let e = explain_path(&p, home, proj, Path::new("/opt/other"));
        assert_eq!(e.read_decision(), Decision::Blocked);
        assert!(!e.credential);
        assert!(e.fix.as_deref().unwrap().contains("--allow-read"));
    }

    // ── explain_domain ──

    fn net_policy(allowed: &[&str], blocked: &[&str], ports: &[u16]) -> NetPolicy {
        NetPolicy {
            allowed_ports: ports.to_vec(),
            allowed_domains: allowed.iter().map(|s| (*s).to_string()).collect(),
            blocked_domains: blocked.iter().map(|s| (*s).to_string()).collect(),
            allow_localhost_ports: Vec::new(),
            allow_localhost_any: false,
            ..Default::default()
        }
    }

    #[test]
    fn allowed_domain_is_allowed() {
        let np = net_policy(&["github.com"], &[], &[443]);
        let e = explain_domain(&np, "github.com", 443, true);
        assert_eq!(e.decision, Decision::Allowed);
        assert_eq!(e.status, "ALLOWED");
    }

    #[test]
    fn unknown_domain_blocked_by_allowlist() {
        let np = net_policy(&["github.com"], &[], &[443]);
        let e = explain_domain(&np, "evil.example", 443, true);
        assert_eq!(e.decision, Decision::Blocked);
        assert_eq!(e.status, "BLOCKED-ALLOWLIST");
        assert!(e.fix.as_deref().unwrap().contains("allowed_domains"));
    }

    #[test]
    fn metadata_ip_blocked_private() {
        // Empty allowlist ⇒ allow-all, so the SSRF guard is what blocks it.
        let np = net_policy(&[], &[], &[443]);
        let e = explain_domain(&np, "169.254.169.254", 443, true);
        assert_eq!(e.decision, Decision::Blocked);
        assert_eq!(e.status, "BLOCKED-PRIVATE");
    }

    #[test]
    fn bad_port_blocked() {
        let np = net_policy(&[], &[], &[443]);
        let e = explain_domain(&np, "github.com", 22, true);
        assert_eq!(e.decision, Decision::Blocked);
        assert_eq!(e.status, "BLOCKED-PORT");
    }

    #[test]
    fn proxy_disabled_is_not_filtered() {
        let np = net_policy(&[], &[], &[443]);
        let e = explain_domain(&np, "anything.example", 443, false);
        assert_eq!(e.decision, Decision::Allowed);
        assert_eq!(e.status, "NO-PROXY");
    }

    // ── explain_exec ──

    fn exec_ctx<'a>(
        gh: &'a GhGuardPolicy,
        git: &'a GitGuardPolicy,
        allow_docker: bool,
    ) -> ExecContext<'a> {
        ExecContext {
            allow_docker,
            allow_tmp_exec: false,
            gh_guard: gh,
            git_guard: git,
            project_dir: Path::new("/home/u/proj"),
        }
    }

    #[test]
    fn docker_blocked_without_allow() {
        let gh = GhGuardPolicy::default();
        let git = GitGuardPolicy::default();
        let ctx = exec_ctx(&gh, &git, false);
        let e = explain_exec(&["docker".into(), "ps".into()], &ctx);
        assert_eq!(e.decision, Decision::Blocked);
        assert!(e.fix.as_deref().unwrap().contains("--allow-docker"));
    }

    #[test]
    fn docker_allowed_with_flag() {
        let gh = GhGuardPolicy::default();
        let git = GitGuardPolicy::default();
        let ctx = exec_ctx(&gh, &git, true);
        let e = explain_exec(&["/usr/bin/docker".into(), "ps".into()], &ctx);
        assert_eq!(e.decision, Decision::Allowed);
    }

    #[test]
    fn git_push_blocked_when_guard_enabled() {
        let gh = GhGuardPolicy::default();
        let git = GitGuardPolicy {
            enabled: true,
            ..GitGuardPolicy::default()
        };
        let ctx = exec_ctx(&gh, &git, false);
        let e = explain_exec(
            &["git".into(), "push".into(), "origin".into(), "main".into()],
            &ctx,
        );
        assert_eq!(e.decision, Decision::Blocked);
    }

    #[test]
    fn git_status_allowed() {
        let gh = GhGuardPolicy::default();
        let git = GitGuardPolicy {
            enabled: true,
            ..GitGuardPolicy::default()
        };
        let ctx = exec_ctx(&gh, &git, false);
        let e = explain_exec(&["git".into(), "status".into()], &ctx);
        assert_eq!(e.decision, Decision::Allowed);
    }

    #[test]
    fn generic_command_runs() {
        let gh = GhGuardPolicy::default();
        let git = GitGuardPolicy::default();
        let ctx = exec_ctx(&gh, &git, false);
        let e = explain_exec(&["node".into(), "app.js".into()], &ctx);
        assert_eq!(e.decision, Decision::Allowed);
    }

    // ── Report verdict & JSON ──

    fn blocked_item(name: &str) -> CheckItem {
        CheckItem {
            name: name.to_string(),
            category: "filesystem".to_string(),
            target: name.to_string(),
            decision: Decision::Blocked,
            expected: Some(Decision::Blocked),
            reason: "r".to_string(),
            fix: None,
            note: None,
        }
    }

    fn allowed_item(name: &str) -> CheckItem {
        CheckItem {
            name: name.to_string(),
            category: "filesystem".to_string(),
            target: name.to_string(),
            decision: Decision::Allowed,
            expected: Some(Decision::Allowed),
            reason: "r".to_string(),
            fix: None,
            note: None,
        }
    }

    #[test]
    fn enforcing_when_all_expectations_met() {
        let items = vec![allowed_item("proj"), blocked_item("ssh")];
        let r = Report::new("copilot".into(), Some("strict".into()), true, items);
        assert!(r.enforcing);
        assert_eq!(r.verified, 1);
        assert!(!r.exit_nonzero());
        assert!(r.render().contains("ENFORCING"));
    }

    #[test]
    fn not_enforcing_when_protection_leaks() {
        let mut leak = blocked_item("ssh");
        leak.decision = Decision::Allowed; // protection failed to block
        let r = Report::new(
            "copilot".into(),
            None,
            true,
            vec![allowed_item("proj"), leak],
        );
        assert!(!r.enforcing);
        assert!(r.exit_nonzero());
        assert!(r.render().contains("NOT ENFORCING"));
    }

    #[test]
    fn json_shape_has_fields() {
        let r = Report::new("copilot".into(), None, true, vec![blocked_item("ssh")]);
        let j = r.to_json();
        assert!(j.contains("\"enforcing\""));
        assert!(j.contains("\"verified\""));
        assert!(j.contains("\"items\""));
        assert!(j.contains("\"decision\": \"blocked\""));
    }
}
