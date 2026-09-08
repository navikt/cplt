//! `cplt doctor`: findings, not inventory.
//!
//! The question doctor answers is "will cplt work on this host for this
//! agent, and if the agent just failed, which enforcement decision caused
//! it?" — offline, without building a sandbox, so it still answers when a
//! launch cannot. The output is written to be pasted into a public issue:
//! paths are `~/…`, token *names* only, and the software inventory stays
//! behind `--verbose`.
//!
//! The rules here are pure functions over what the launch already resolved
//! (`Resolved`, the generated `LandlockPolicy`, the agent), so they cannot
//! answer from fewer inputs than the launch uses (#447). `main.rs` gathers
//! those inputs and prints; this module decides.

use crate::agent::Agent;
use crate::sandbox::LandlockPolicy;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The agent will not start, or cplt will not launch.
    Blocking,
    /// Something will fail mid-session, or a protection is silently off.
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub message: String,
    pub fix: Option<String>,
}

impl Finding {
    #[must_use]
    pub fn blocking(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            level: Level::Blocking,
            message: message.into(),
            fix: Some(fix.into()),
        }
    }

    #[must_use]
    pub fn warning(message: impl Into<String>, fix: Option<String>) -> Self {
        Self {
            level: Level::Warning,
            message: message.into(),
            fix,
        }
    }
}

/// `~/…` for anything under `home`, so a pasted report does not carry the
/// username.
#[must_use]
pub fn tilde(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

// ── Rule: tracked secrets vs. the .env deny ────────────────────

/// Whether a file *name* is one the `.env` deny covers.
///
/// Mirrors `sandbox_policy::SENSITIVE_PROJECT_PATTERNS` (`\.env$`, `\.env\..*`,
/// and the `.pem/.key/.p12/.pfx/.jks` suffixes) without a regex engine: the
/// list is seven fixed shapes and a test pins them together.
#[must_use]
pub fn is_sensitive_name(name: &str) -> bool {
    name == ".env"
        || name.ends_with(".env")
        || name.contains(".env.")
        || [".pem", ".key", ".p12", ".pfx", ".jks"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// The tracked paths the `.env` deny applies to.
#[must_use]
pub fn tracked_sensitive_files<'a>(tracked: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    tracked
        .into_iter()
        .filter(|p| {
            Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_sensitive_name)
        })
        .map(str::to_string)
        .collect()
}

/// A tracked secret under the `.env` deny breaks every git command that hashes
/// the index (`add`, `diff`, `stash`, `commit -a`) with `cannot hash`.
#[must_use]
pub fn tracked_env_finding(files: &[String], allow_env_files: bool) -> Option<Finding> {
    if allow_env_files || files.is_empty() {
        return None;
    }
    let list = files.join(", ");
    let first = &files[0];
    Some(Finding::warning(
        format!(
            "{list} {} tracked in git and allow_env_files is off: git add/diff/stash/commit -a \
             will fail with `cannot hash`.",
            if files.len() == 1 { "is" } else { "are" }
        ),
        Some(format!(
            "git rm --cached {first} && echo {first} >> .gitignore  (or sandbox.allow_env_files = true)"
        )),
    ))
}

// ── Rule: Pi's trust lock vs. the read-only agent root ─────────

/// Newest Pi release that does not take the trust lock. Pi `main` after
/// f53ac11 (2026-09-08) does `mkdir ~/.pi/agent/trust.json.lock` before a
/// session exists (#449).
const PI_LAST_LOCKLESS: &str = "0.85.1";

fn version_tuple(v: &str) -> Option<Vec<u64>> {
    v.trim_start_matches('v')
        .split(['-', '+'])
        .next()?
        .split('.')
        .map(|part| part.parse().ok())
        .collect()
}

/// Whether the resolved policy grants `dir` itself read-only.
fn dir_is_read_only(policy: &LandlockPolicy, dir: &Path) -> bool {
    policy
        .fs_rules
        .iter()
        .find(|r| r.path == dir)
        .is_some_and(|r| !r.access.write)
}

/// Pi creates a lock *directory* in `~/.pi/agent` to read `trust.json`, and
/// that root is granted read-only in every regime — Landlock rule and, when
/// bubblewrap is active, the mount too — so no bubblewrap state changes the
/// answer. Blocking when the installed Pi is known to take the lock, a warning
/// when its version could not be read.
#[must_use]
pub fn pi_lock_finding(
    agent: Agent,
    policy: &LandlockPolicy,
    home: &Path,
    pi_version: Option<&str>,
) -> Option<Finding> {
    if agent != Agent::Pi {
        return None;
    }
    let root = home.join(".pi/agent");
    if !dir_is_read_only(policy, &root) {
        return None;
    }
    let takes_lock = pi_version
        .and_then(version_tuple)
        .map(|v| v > version_tuple(PI_LAST_LOCKLESS).unwrap_or_default());
    let fix = "run pi outside cplt until a cplt release grants the lock, or pin Pi to \
               0.85.1 (npm i -g @earendil-works/pi-coding-agent@0.85.1)";
    match takes_lock {
        Some(false) => None,
        Some(true) => Some(Finding::blocking(
            format!(
                "Pi will not start: ~/.pi/agent is read-only in this run, and Pi {} takes a \
                 write lock there (trust.json.lock) before a session exists.",
                pi_version.unwrap_or_default()
            ),
            fix,
        )),
        None => Some(Finding::warning(
            format!(
                "~/.pi/agent is read-only in this run; Pi newer than {PI_LAST_LOCKLESS} takes a \
                 write lock there (trust.json.lock) and will not start. Could not read the \
                 installed Pi's version."
            ),
            Some(fix.to_string()),
        )),
    }
}

// ── Rule: shims resolving outside a granted root ───────────────

/// A `(name, path-as-found-on-PATH)` pair; the path must be the PATH entry,
/// not its canonical target, or there is no shim left to inspect.
pub type ToolOnPath<'a> = (&'a str, &'a Path);

/// One warning per tool whose symlink target the policy does not grant
/// execute on. Same predicate the launch warns with (#390).
#[must_use]
pub fn shim_findings(
    policy: &LandlockPolicy,
    tools: &[ToolOnPath<'_>],
    home: &Path,
) -> Vec<Finding> {
    tools
        .iter()
        .filter_map(|(name, path)| {
            let target = crate::check::shim_target_without_exec(policy, path)?;
            let dir = target.parent().unwrap_or(&target).to_path_buf();
            Some(Finding::warning(
                format!(
                    "{name} is a shim resolving to {}, which this run does not grant execute on: \
                     running it fails with exit 126 and no message.",
                    tilde(&target, home)
                ),
                Some(format!(
                    "--allow-exec {} (or [sandbox] allow.exec)",
                    tilde(&dir, home)
                )),
            ))
        })
        .collect()
}

// ── Bubblewrap: three states, not a PATH lookup ────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bubblewrap {
    /// Present and able to create the namespaces the launch needs.
    Usable(PathBuf),
    /// On disk, but the probe the launch runs fails (no user namespaces, a
    /// hardened kernel, some WSL configs). Auto-detect falls back silently.
    Unusable { path: PathBuf, reason: String },
    /// Not in any trusted directory.
    NotInstalled,
    /// `use_bubblewrap = false` / `--no-bubblewrap`.
    Disabled,
    /// Not a Linux host.
    NotApplicable,
}

impl Bubblewrap {
    #[must_use]
    pub fn active(&self) -> bool {
        matches!(self, Self::Usable(_))
    }

    /// The `bubblewrap:` fragment of the enforcement line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Usable(_) => "bubblewrap: active".to_string(),
            Self::Unusable { reason, .. } => format!("bubblewrap: installed, {reason}"),
            Self::NotInstalled => "bubblewrap: not installed".to_string(),
            Self::Disabled => "bubblewrap: disabled by config".to_string(),
            Self::NotApplicable => String::new(),
        }
    }
}

/// What the launch's own `bubblewrap::resolve` would conclude, minus the
/// wrapper: the same trusted-directory lookup and the same `bwrap … /bin/true`
/// namespace probe, run against an empty rule set.
#[cfg(target_os = "linux")]
#[must_use]
pub fn bubblewrap_state(use_bubblewrap: Option<bool>) -> Bubblewrap {
    use crate::sandbox::bubblewrap_probe;
    if use_bubblewrap == Some(false) {
        return Bubblewrap::Disabled;
    }
    let Some(path) = bubblewrap_probe::check_availability() else {
        return Bubblewrap::NotInstalled;
    };
    match bubblewrap_probe::test_empty(&path) {
        Ok(()) => Bubblewrap::Usable(path),
        Err(reason) => Bubblewrap::Unusable {
            path,
            reason: first_line(&reason),
        },
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn bubblewrap_state(_use_bubblewrap: Option<bool>) -> Bubblewrap {
    Bubblewrap::NotApplicable
}

#[cfg(target_os = "linux")]
fn first_line(s: &str) -> String {
    s.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("probe failed")
        .to_string()
}

// ── Rendering ──────────────────────────────────────────────────

/// The findings block plus the summary line. `ok` is the one-line "what is
/// fine" roll-up; `header` is printed by the caller, which owns the inputs.
#[must_use]
pub fn render(findings: &[Finding], ok: &[String], verbose_hint: bool) -> String {
    use crate::ui::{GREEN, RED, RESET, YELLOW, stdout_color};
    use std::fmt::Write as _;
    let mut out = String::new();
    let blocking = findings
        .iter()
        .filter(|f| f.level == Level::Blocking)
        .count();
    let warnings = findings.len() - blocking;

    for f in findings {
        let (sym, color) = match f.level {
            Level::Blocking => ("✗", RED),
            Level::Warning => ("⚠", YELLOW),
        };
        let _ = writeln!(
            out,
            "{}{sym}{} {}",
            stdout_color(color),
            stdout_color(RESET),
            f.message
        );
        if let Some(fix) = &f.fix {
            let _ = writeln!(out, "  fix: {fix}");
        }
    }
    if !ok.is_empty() {
        let joined = ok
            .iter()
            .map(|s| format!("{}✓{} {s}", stdout_color(GREEN), stdout_color(RESET)))
            .collect::<Vec<_>>()
            .join(" · ");
        let _ = writeln!(out, "{joined}");
    }
    let _ = writeln!(out);
    let verdict = if blocking > 0 {
        format!(
            "{}{blocking} blocking, {warnings} warning{}.{}",
            stdout_color(RED),
            if warnings == 1 { "" } else { "s" },
            stdout_color(RESET)
        )
    } else if warnings > 0 {
        format!(
            "{}0 blocking, {warnings} warning{}.{}",
            stdout_color(YELLOW),
            if warnings == 1 { "" } else { "s" },
            stdout_color(RESET)
        )
    } else {
        format!(
            "{}No problems found.{}",
            stdout_color(GREEN),
            stdout_color(RESET)
        )
    };
    let hint = if verbose_hint {
        " `cplt doctor --verbose` for the inventory, `cplt check` to probe enforcement."
    } else {
        " `cplt check` to probe enforcement."
    };
    let _ = writeln!(out, "{verdict}{hint}");
    out
}

/// Exit non-zero iff something is blocking — the contract the old doctor had
/// for its "critical" checks.
#[must_use]
pub fn exit_nonzero(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.level == Level::Blocking)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{FsAccess, FsRule};

    fn policy(rules: Vec<(&str, bool, bool)>) -> LandlockPolicy {
        LandlockPolicy {
            fs_rules: rules
                .into_iter()
                .map(|(p, write, execute)| FsRule {
                    path: PathBuf::from(p),
                    access: FsAccess {
                        read: true,
                        write,
                        execute,
                        ioctl: false,
                    },
                })
                .collect(),
            net_rules: vec![],
            restrict_net_connect: false,
            proxy_forced: false,
            home_dir: PathBuf::from("/home/u"),
            precreate_dirs: vec![],
        }
    }

    #[test]
    fn tilde_hides_the_username() {
        let home = Path::new("/Users/hans");
        assert_eq!(
            tilde(Path::new("/Users/hans/.pi/agent"), home),
            "~/.pi/agent"
        );
        assert_eq!(tilde(home, home), "~");
        assert_eq!(tilde(Path::new("/usr/bin/git"), home), "/usr/bin/git");
    }

    #[test]
    fn sensitive_names_track_the_policy_patterns() {
        for hit in [
            ".env",
            ".env.local",
            "prod.env",
            "id.pem",
            "server.key",
            "k.p12",
            "k.pfx",
            "k.jks",
        ] {
            assert!(is_sensitive_name(hit), "{hit} should match");
        }
        for miss in [
            ".envrc",
            "env.ts",
            "keychain.rs",
            "README.md",
            ".environment",
        ] {
            assert!(!is_sensitive_name(miss), "{miss} should not match");
        }
    }

    #[test]
    fn tracked_env_finding_needs_a_tracked_file_and_the_deny() {
        let files = tracked_sensitive_files(["src/main.rs", "config/.env.local", ".gitignore"]);
        assert_eq!(files, vec!["config/.env.local".to_string()]);
        assert!(
            tracked_env_finding(&files, true).is_none(),
            "deny off: nothing to say"
        );
        assert!(
            tracked_env_finding(&[], false).is_none(),
            "nothing tracked: nothing to say"
        );
        let f = tracked_env_finding(&files, false).expect("finding");
        assert_eq!(f.level, Level::Warning);
        assert!(f.message.contains("cannot hash"));
        assert!(
            f.fix
                .as_deref()
                .unwrap()
                .contains("git rm --cached config/.env.local")
        );
    }

    #[test]
    fn pi_lock_rule_is_version_gated_and_pi_only() {
        let home = Path::new("/home/u");
        let ro_root = policy(vec![("/home/u/.pi/agent", false, false)]);
        assert!(pi_lock_finding(Agent::Copilot, &ro_root, home, Some("1.0.0")).is_none());
        assert!(
            pi_lock_finding(Agent::Pi, &ro_root, home, Some("0.85.1")).is_none(),
            "0.85.1 predates the lock"
        );
        let blocking = pi_lock_finding(Agent::Pi, &ro_root, home, Some("0.86.0")).unwrap();
        assert_eq!(blocking.level, Level::Blocking);
        assert!(blocking.message.contains("trust.json.lock"));
        let unknown = pi_lock_finding(Agent::Pi, &ro_root, home, None).unwrap();
        assert_eq!(unknown.level, Level::Warning);
        // A policy that grants the root writable has nothing to warn about.
        let rw_root = policy(vec![("/home/u/.pi/agent", true, false)]);
        assert!(pi_lock_finding(Agent::Pi, &rw_root, home, Some("0.86.0")).is_none());
    }

    #[test]
    fn version_tuple_ignores_prerelease_suffixes() {
        assert_eq!(version_tuple("v0.86.0-beta.1"), Some(vec![0, 86, 0]));
        assert!(version_tuple("0.86.0").unwrap() > version_tuple("0.85.1").unwrap());
        assert!(version_tuple("0.85.10").unwrap() > version_tuple("0.85.1").unwrap());
        assert_eq!(version_tuple("nope"), None);
    }

    #[test]
    fn shim_findings_use_the_launch_predicate() {
        // A real symlink whose target is outside every exec grant.
        let tmp = std::env::temp_dir().join(format!("cplt-doctor-shim-{}", std::process::id()));
        let granted = tmp.join("granted");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("real");
        std::fs::write(&target, "").unwrap();
        // The shim is named by its canonical directory, as a PATH entry the
        // launch canonicalized would be; the predicate compares paths textually.
        let granted_c = std::fs::canonicalize(&granted).unwrap();
        let shim = granted_c.join("node");
        std::os::unix::fs::symlink(&target, &shim).unwrap();
        let p = policy(vec![(granted_c.to_str().unwrap(), false, true)]);

        let found = shim_findings(&p, &[("node", shim.as_path())], &tmp);
        assert_eq!(found.len(), 1);
        assert!(found[0].message.starts_with("node is a shim"));
        assert!(found[0].fix.as_deref().unwrap().contains("--allow-exec"));

        // The target granted too: not a shim problem.
        let outside_c = std::fs::canonicalize(&outside).unwrap();
        let p2 = policy(vec![
            (granted_c.to_str().unwrap(), false, true),
            (outside_c.to_str().unwrap(), false, true),
        ]);
        assert!(shim_findings(&p2, &[("node", shim.as_path())], &tmp).is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn render_puts_the_verdict_last_and_counts_levels() {
        let findings = vec![
            Finding::blocking("Pi will not start", "run outside"),
            Finding::warning("x is tracked", None),
        ];
        let out = render(&findings, &["auth: gh CLI".to_string()], true);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("Pi will not start"));
        assert_eq!(lines[1].trim(), "fix: run outside");
        assert!(lines[2].contains("x is tracked"));
        assert!(lines[3].contains("auth: gh CLI"));
        assert!(lines.last().unwrap().starts_with("1 blocking, 1 warning."));
        assert!(lines.last().unwrap().contains("--verbose"));
        assert!(exit_nonzero(&findings));
        assert!(!exit_nonzero(&findings[1..]));
        assert!(render(&[], &[], false).contains("No problems found."));
    }
}
