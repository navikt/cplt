//! Post-session PROJECT-CHANGE audit report (issue #54, Phase 1).
//!
//! # Why this is trustworthy
//!
//! cplt runs *outside* the sandbox and exec's the agent as a child process.
//! Everything measured here happens in the **parent** process — the baseline is
//! captured before the child starts and the report is generated after it exits,
//! both beyond the sandboxed agent's reach. The agent can neither observe nor
//! tamper with these measurements.
//!
//! The git diff is taken against a **pinned baseline commit SHA** captured
//! before the run (`git rev-parse HEAD`), *not* against a moving `HEAD`. This is
//! the load-bearing property: an agent that runs `git commit`, `git reset`, or
//! `git checkout` inside the session cannot hide its net changes, because we
//! always diff the real working tree against the exact commit it started from.
//!
//! # Scope (Phase 1)
//!
//! Git working-tree changes plus session timing only. Network and denial
//! auditing are deliberately **out of scope** here — they are strictly weaker
//! than the sandbox (network is incomplete unless proxy-forced; Linux emits no
//! denial log) and belong to later phases with explicit honesty caveats. This
//! module never claims more than git + timing can prove.

use crate::ui;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A matcher against a changed path, used to classify sensitive files.
///
/// Kept as a small data enum so the pattern → reason mapping lives in a single
/// testable table ([`SENSITIVE_PATTERNS`]) rather than scattered conditionals.
#[derive(Debug, Clone, Copy)]
enum Matcher {
    /// Exact basename match (e.g. `Dockerfile`, `package.json`).
    Name(&'static str),
    /// Basename suffix match (e.g. `.sh`, `.lock`).
    Suffix(&'static str),
    /// Basename prefix match (e.g. `docker-compose`, `.env`, `Taskfile`).
    Prefix(&'static str),
    /// Basename prefix AND suffix (e.g. `requirements*.txt`).
    PrefixSuffix(&'static str, &'static str),
    /// Directory-prefix match on the full repo-relative path
    /// (e.g. `.github/workflows`).
    Dir(&'static str),
}

/// Sensitive-path classification table: each matcher maps to a short reason.
///
/// Order matters only for the reason string when multiple entries match; the
/// first match wins. Patterns cover CI/CD, container, dependency manifests and
/// lockfiles, shell scripts, build automation, env files, tool config, and the
/// sandbox config itself — categories where an unreviewed change is high-risk.
const SENSITIVE_PATTERNS: &[(Matcher, &str)] = &[
    (Matcher::Dir(".github/workflows"), "CI/CD workflow"),
    (Matcher::Dir(".github/actions"), "CI/CD action"),
    (Matcher::Name("Dockerfile"), "container image"),
    (Matcher::Prefix("docker-compose"), "container config"),
    (Matcher::Name("package.json"), "dependency manifest"),
    (Matcher::Name("Cargo.lock"), "dependency lockfile"),
    (Matcher::Name("go.mod"), "dependency manifest"),
    (Matcher::Name("go.sum"), "dependency lockfile"),
    (Matcher::Name("pyproject.toml"), "dependency manifest"),
    (
        Matcher::PrefixSuffix("requirements", ".txt"),
        "dependency manifest",
    ),
    (Matcher::Suffix(".lock"), "dependency lockfile"),
    (Matcher::Suffix(".sh"), "shell script"),
    (Matcher::Name("Makefile"), "build automation"),
    (Matcher::Name("Justfile"), "build automation"),
    (Matcher::Prefix("Taskfile"), "build automation"),
    (Matcher::Prefix(".env"), "env file"),
    (Matcher::Name("mise.toml"), "tool config"),
    (Matcher::Name(".tool-versions"), "tool config"),
    (Matcher::Name(".cplt.toml"), "sandbox config"),
];

/// Return the basename (path component after the last `/`) of a repo-relative
/// path. git always emits forward-slash separators, so this is portable.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn matches(m: &Matcher, path: &str, base: &str) -> bool {
    match m {
        Matcher::Name(n) => base == *n,
        Matcher::Suffix(s) => base.ends_with(s),
        Matcher::Prefix(p) => base.starts_with(p),
        Matcher::PrefixSuffix(p, s) => base.starts_with(p) && base.ends_with(s),
        Matcher::Dir(d) => path.starts_with(&format!("{d}/")) || path.contains(&format!("/{d}/")),
    }
}

/// Classify a changed repo-relative path against the sensitive-pattern table.
///
/// Returns `Some(reason)` for the first matching pattern, or `None` for
/// ordinary source files. Pure function — the sole classification entry point,
/// unit-tested against every pattern category.
pub fn classify_path(path: &str) -> Option<&'static str> {
    let base = basename(path);
    SENSITIVE_PATTERNS
        .iter()
        .find(|(m, _)| matches(m, path, base))
        .map(|(_, reason)| *reason)
}

/// A single parsed `git diff --numstat` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumStat {
    pub path: String,
    /// Added lines, or `None` for binary files (numstat prints `-`).
    pub added: Option<u64>,
    /// Deleted lines, or `None` for binary files.
    pub deleted: Option<u64>,
}

/// Parse the output of `git diff --numstat <sha>`.
///
/// Each line is `<added>\t<deleted>\t<path>`; binary files use `-` for the
/// counts. Pure function so the net-change computation is unit-testable without
/// invoking git.
pub fn parse_numstat(output: &str) -> Vec<NumStat> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let added = parts.next()?;
            let deleted = parts.next()?;
            let path = parts.next()?;
            if path.is_empty() {
                return None;
            }
            Some(NumStat {
                path: path.to_string(),
                added: added.parse::<u64>().ok(),
                deleted: deleted.parse::<u64>().ok(),
            })
        })
        .collect()
}

/// Parse the untracked (`??`) entries from `git status --porcelain -uall`.
///
/// Returns a sorted set of repo-relative paths. Pure function — the before/after
/// untracked sets feed [`new_untracked`].
pub fn parse_untracked(porcelain: &str) -> BTreeSet<String> {
    porcelain
        .lines()
        .filter_map(|line| line.strip_prefix("?? "))
        .map(unquote_path)
        .collect()
}

/// git porcelain quotes paths containing special characters in double quotes.
/// Strip the surrounding quotes for display; leave other paths untouched.
fn unquote_path(raw: &str) -> String {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw[1..raw.len() - 1].to_string()
    } else {
        raw.to_string()
    }
}

/// Net-new untracked files = files untracked *after* the session that were not
/// untracked *before* it (set difference `after − before`).
///
/// Pure function. A file that was untracked before and still is, is not new; a
/// file the agent created is. Files the agent created *and committed* appear in
/// the tracked diff instead (they are no longer untracked), so there is no
/// double counting.
pub fn new_untracked(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after.difference(before).cloned().collect()
}

/// A single changed file in the final report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    /// Added lines (tracked changes only; `None` for untracked/binary).
    pub added: Option<u64>,
    /// Deleted lines (tracked changes only; `None` for untracked/binary).
    pub deleted: Option<u64>,
    /// True when this file appeared as a new untracked file during the session.
    pub is_new_untracked: bool,
    /// `Some(reason)` when the path matches a sensitive pattern.
    pub sensitive: Option<&'static str>,
}

/// The generated audit report, ready to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditReport {
    /// The project directory is not a git repository, or has no commits — a net
    /// change audit is not possible. Timing is still reported.
    Unavailable { duration: Duration, exit_code: u8 },
    /// A net-change audit against the pinned baseline commit.
    Available {
        duration: Duration,
        exit_code: u8,
        changes: Vec<FileChange>,
        total_added: u64,
        total_deleted: u64,
    },
}

/// Baseline snapshot captured **before** the sandboxed agent runs.
///
/// Holds the pinned commit SHA and the pre-run untracked set, plus a start
/// [`Instant`] for duration. All fields are captured in the parent process
/// before `exec_sandboxed`, so they cannot be influenced by the agent.
pub struct Baseline {
    start: Instant,
    project_dir: PathBuf,
    /// The pinned commit SHA from `git rev-parse HEAD`, or `None` when the
    /// project is not a git repo / has no commits ("no baseline").
    pinned_sha: Option<String>,
    /// Untracked paths present before the run.
    before_untracked: BTreeSet<String>,
}

impl Baseline {
    /// Capture the baseline for `project_dir`. Never panics: git absence, a
    /// non-repo directory, or an empty repo all degrade cleanly to "no
    /// baseline" (reported later as change audit unavailable).
    pub fn capture(project_dir: &Path) -> Self {
        let start = Instant::now();
        // The pinned SHA. If HEAD does not resolve (not a repo, or no commits),
        // we record no baseline rather than erroring.
        let pinned_sha = git_output(project_dir, &["rev-parse", "HEAD"])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let before_untracked = if pinned_sha.is_some() {
            git_output(project_dir, &["status", "--porcelain", "-uall"])
                .map(|s| parse_untracked(&s))
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        Self {
            start,
            project_dir: project_dir.to_path_buf(),
            pinned_sha,
            before_untracked,
        }
    }

    /// Generate the report after the agent exits. Diffs the current working tree
    /// against the pinned baseline SHA (capturing changes even if the agent
    /// committed or reset them) and computes net-new untracked files.
    pub fn finish(self, exit_code: u8) -> AuditReport {
        let duration = self.start.elapsed();
        let Some(sha) = self.pinned_sha else {
            return AuditReport::Unavailable {
                duration,
                exit_code,
            };
        };

        // Net TRACKED changes vs the *pinned* commit — not moving HEAD.
        let tracked = git_output(&self.project_dir, &["diff", "--numstat", &sha])
            .map(|out| parse_numstat(&out))
            .unwrap_or_default();

        // Net NEW untracked files: after-untracked MINUS before-untracked.
        let after_untracked = git_output(&self.project_dir, &["status", "--porcelain", "-uall"])
            .map(|s| parse_untracked(&s))
            .unwrap_or_default();
        let new_files = new_untracked(&self.before_untracked, &after_untracked);

        let mut total_added = 0u64;
        let mut total_deleted = 0u64;
        let mut changes: Vec<FileChange> = Vec::new();

        for ns in tracked {
            total_added += ns.added.unwrap_or(0);
            total_deleted += ns.deleted.unwrap_or(0);
            let sensitive = classify_path(&ns.path);
            changes.push(FileChange {
                path: ns.path,
                added: ns.added,
                deleted: ns.deleted,
                is_new_untracked: false,
                sensitive,
            });
        }
        for path in new_files {
            let sensitive = classify_path(&path);
            changes.push(FileChange {
                path,
                added: None,
                deleted: None,
                is_new_untracked: true,
                sensitive,
            });
        }

        changes.sort_by(|a, b| a.path.cmp(&b.path));

        AuditReport::Available {
            duration,
            exit_code,
            changes,
            total_added,
            total_deleted,
        }
    }
}

impl AuditReport {
    /// Print the report to stderr via the shared `ui` helpers.
    pub fn print(&self) {
        match self {
            AuditReport::Unavailable {
                duration,
                exit_code,
            } => {
                ui::info(&format!(
                    "Session ended (exit {exit_code}, {})",
                    human_duration(*duration)
                ));
                ui::warn(
                    "change audit unavailable: project is not a git repository (or has no commits)",
                );
            }
            AuditReport::Available {
                duration,
                exit_code,
                changes,
                total_added,
                total_deleted,
            } => {
                ui::info(&format!(
                    "Session ended (exit {exit_code}, {})",
                    human_duration(*duration)
                ));
                if changes.is_empty() {
                    ui::info("no project file changes");
                    return;
                }
                ui::info(&format!(
                    "Project changes: {} file{} (+{total_added} -{total_deleted})",
                    changes.len(),
                    if changes.len() == 1 { "" } else { "s" },
                ));
                for c in changes {
                    let counts = format_counts(c);
                    match c.sensitive {
                        Some(reason) => ui::warn(&format!("  {}{counts}  ⚠️  {reason}", c.path)),
                        None => ui::info(&format!("  {}{counts}", c.path)),
                    }
                }
            }
        }
    }
}

/// Format the per-file `+adds -dels` (or `new file`) suffix for a change line.
fn format_counts(c: &FileChange) -> String {
    if c.is_new_untracked && c.added.is_none() {
        return "  (new file)".to_string();
    }
    match (c.added, c.deleted) {
        (Some(a), Some(d)) => format!("  +{a} -{d}"),
        _ => "  (binary)".to_string(),
    }
}

/// Render a duration as `Xm Ys` (or `Ys` under a minute).
fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    let mins = secs / 60;
    let rem = secs % 60;
    if mins > 0 {
        format!("{mins}m {rem}s")
    } else {
        format!("{rem}s")
    }
}

/// Run `git` in `project_dir`, returning stdout on success or `None` on any
/// failure (git missing, non-zero exit, non-UTF8). Never panics — git absence
/// must degrade cleanly.
fn git_output(project_dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(project_dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Wrap a sandboxed exec with the audit lifecycle: capture the baseline just
/// before the closure runs the agent, then generate and print the report after
/// it exits. Both `main.rs` exec sites call this so the wiring cannot diverge.
///
/// When `enabled` is false (`--no-audit`, `--quiet`, or config `audit = false`)
/// the closure runs with no measurement or output at all.
pub fn run<F: FnOnce() -> u8>(project_dir: &Path, enabled: bool, exec: F) -> u8 {
    if !enabled {
        return exec();
    }
    let baseline = Baseline::capture(project_dir);
    let exit_code = exec();
    baseline.finish(exit_code).print();
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn classifier_flags_ci_workflows() {
        assert_eq!(
            classify_path(".github/workflows/ci.yml"),
            Some("CI/CD workflow")
        );
        assert_eq!(
            classify_path(".github/actions/setup/action.yml"),
            Some("CI/CD action")
        );
    }

    #[test]
    fn classifier_flags_containers() {
        assert_eq!(classify_path("Dockerfile"), Some("container image"));
        assert_eq!(classify_path("deploy/Dockerfile"), Some("container image"));
        assert_eq!(
            classify_path("docker-compose.yml"),
            Some("container config")
        );
        assert_eq!(
            classify_path("docker-compose.override.yaml"),
            Some("container config")
        );
    }

    #[test]
    fn classifier_flags_dependency_manifests_and_lockfiles() {
        assert_eq!(classify_path("package.json"), Some("dependency manifest"));
        assert_eq!(classify_path("Cargo.lock"), Some("dependency lockfile"));
        assert_eq!(classify_path("go.mod"), Some("dependency manifest"));
        assert_eq!(classify_path("go.sum"), Some("dependency lockfile"));
        assert_eq!(classify_path("pyproject.toml"), Some("dependency manifest"));
        assert_eq!(
            classify_path("requirements.txt"),
            Some("dependency manifest")
        );
        assert_eq!(
            classify_path("requirements-dev.txt"),
            Some("dependency manifest")
        );
        assert_eq!(classify_path("yarn.lock"), Some("dependency lockfile"));
    }

    #[test]
    fn classifier_flags_scripts_and_build_automation() {
        assert_eq!(classify_path("scripts/deploy.sh"), Some("shell script"));
        assert_eq!(classify_path("Makefile"), Some("build automation"));
        assert_eq!(classify_path("Justfile"), Some("build automation"));
        assert_eq!(classify_path("Taskfile.yml"), Some("build automation"));
    }

    #[test]
    fn classifier_flags_env_tool_and_sandbox_config() {
        assert_eq!(classify_path(".env"), Some("env file"));
        assert_eq!(classify_path(".env.production"), Some("env file"));
        assert_eq!(classify_path("mise.toml"), Some("tool config"));
        assert_eq!(classify_path(".tool-versions"), Some("tool config"));
        assert_eq!(classify_path(".cplt.toml"), Some("sandbox config"));
    }

    #[test]
    fn classifier_ignores_ordinary_source() {
        assert_eq!(classify_path("src/foo.rs"), None);
        assert_eq!(classify_path("src/main.rs"), None);
        assert_eq!(classify_path("README.md"), None);
        assert_eq!(classify_path("docs/design.md"), None);
        // A file merely named like a dir pattern but not under it is not CI/CD.
        assert_eq!(classify_path("workflows.rs"), None);
    }

    #[test]
    fn new_untracked_is_after_minus_before() {
        let before = set(&["notes.txt"]);
        let after = set(&["notes.txt", "evil.sh", "out/artifact.bin"]);
        let new = new_untracked(&before, &after);
        assert_eq!(
            new,
            vec!["evil.sh".to_string(), "out/artifact.bin".to_string()]
        );
    }

    #[test]
    fn new_untracked_ignores_preexisting_and_removed() {
        // A file untracked both before and after is not new; a file that was
        // untracked before but is gone after does not appear.
        let before = set(&["a.txt", "b.txt"]);
        let after = set(&["a.txt", "c.txt"]);
        assert_eq!(new_untracked(&before, &after), vec!["c.txt".to_string()]);
    }

    #[test]
    fn parse_numstat_parses_counts_and_binary() {
        let out = "40\t2\tsrc/main.rs\n0\t10\tREADME.md\n-\t-\tlogo.png\n";
        let parsed = parse_numstat(out);
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0],
            NumStat {
                path: "src/main.rs".to_string(),
                added: Some(40),
                deleted: Some(2),
            }
        );
        assert_eq!(parsed[2].added, None);
        assert_eq!(parsed[2].deleted, None);
    }

    #[test]
    fn parse_untracked_extracts_question_entries() {
        let porcelain = " M src/main.rs\n?? new.txt\n?? sub/dir/x.sh\nA  staged.rs\n";
        let untracked = parse_untracked(porcelain);
        assert_eq!(untracked, set(&["new.txt", "sub/dir/x.sh"]));
    }

    #[test]
    fn finish_reports_unavailable_without_baseline() {
        let base = Baseline {
            start: Instant::now(),
            project_dir: PathBuf::from("/nonexistent"),
            pinned_sha: None,
            before_untracked: BTreeSet::new(),
        };
        match base.finish(0) {
            AuditReport::Unavailable { exit_code, .. } => assert_eq!(exit_code, 0),
            other @ AuditReport::Available { .. } => {
                panic!("expected Unavailable, got {other:?}")
            }
        }
    }
}
