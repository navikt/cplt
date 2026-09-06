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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Upper bound on any single git invocation. The audit runs on EVERY sandboxed
/// start (baseline capture) and after exit; a hung git (NFS stall, index-lock
/// contention, corrupt repo) must never hang cplt. On timeout the child is
/// killed and the query degrades to a failure (`None`) → an honest "incomplete"
/// report rather than a false "clean" one.
const GIT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`run`] waits, after the process cplt actually waited for has been
/// reaped, for the rest of the session's process tree to exit.
///
/// Costs nothing in the normal case: a session that leaves nothing behind
/// closes the last copy of the probe descriptor as it exits, so the wait
/// returns at once. The bound only bites when something really is still alive,
/// and then it is short — a legitimate background process the user wanted is
/// left running and named in the report, not killed.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(2);

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
/// lockfiles, package-registry credentials, private keys, shell scripts, build
/// automation, env files, tool config, and the sandbox config itself —
/// categories where an unreviewed change is high-risk.
const SENSITIVE_PATTERNS: &[(Matcher, &str)] = &[
    (Matcher::Dir(".github/workflows"), "CI/CD workflow"),
    (Matcher::Dir(".github/actions"), "CI/CD action"),
    // Non-GitHub CI: NAV uses GitLab in places, so these matter too.
    (Matcher::Name(".gitlab-ci.yml"), "CI/CD"),
    (Matcher::Name("Jenkinsfile"), "CI/CD"),
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
    // The npm-family lockfiles do NOT end in `.lock`, so the generic `.lock`
    // suffix below misses them. Editing e.g. package-lock.json integrity hashes
    // or resolved URLs is a supply-chain vector — flag them explicitly.
    (Matcher::Name("package-lock.json"), "dependency lockfile"),
    (Matcher::Name("npm-shrinkwrap.json"), "dependency lockfile"),
    (Matcher::Name("pnpm-lock.yaml"), "dependency lockfile"),
    (Matcher::Name("bun.lockb"), "dependency lockfile"),
    (Matcher::Suffix(".lock"), "dependency lockfile"),
    // Package-registry config can carry auth tokens or redirect installs to a
    // hostile registry (dependency-confusion / token exfiltration).
    (
        Matcher::Name(".npmrc"),
        "package registry credentials/config",
    ),
    (
        Matcher::Name(".pypirc"),
        "package registry credentials/config",
    ),
    // Private keys / SSH identities.
    (Matcher::Suffix(".pem"), "private key / credential"),
    (Matcher::Suffix(".key"), "private key / credential"),
    (Matcher::Name("id_rsa"), "private key / credential"),
    (Matcher::Name("id_ed25519"), "private key / credential"),
    (Matcher::Name("id_ecdsa"), "private key / credential"),
    (Matcher::Name("id_dsa"), "private key / credential"),
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

/// Render a git-supplied path safe for the terminal.
///
/// SECURITY (GHSA-c47q-c3c8-7wrf): with `-z`, git emits paths **verbatim** —
/// every byte except `/` and NUL is whatever the sandboxed session named its
/// file. The report is printed with `ui::info`/`ui::warn`, which are bare
/// `eprintln!`, so those bytes reached the terminal unfiltered. A file named
/// `\r\x1b[2K\x1b[1A\x1b[2K[cplt] no project file changes` did not just garble a
/// line: CR + erase-line + cursor-up + erase-line rewrote the "Project changes:
/// 1 file" line above it, so a session that wrote a file reported itself clean.
/// The audit is what the user reads to decide whether to trust the session, and
/// the session was writing it.
///
/// Escaping happens HERE, at the parse boundary, rather than at the print
/// sites: this is where git's untrusted bytes enter the process, and it leaves
/// nothing hostile inside the `pub` [`FileChange`]/[`NumStat`] structs for the
/// classifier, the untracked set difference, this module's two print arms, or a
/// future consumer to re-emit. Nothing downstream needs the raw path — the
/// audit never opens these files, it only reports them.
///
/// `escape_debug`, not `escape_default`, for the reason pinned in
/// `src/proxy.rs` (PR #221): `escape_default` mangles every non-ASCII name into
/// `\u{...}` noise, and a Norwegian filename must stay readable. `escape_debug`
/// leaves printable Unicode alone while covering C0, C1, DEL, bidi overrides
/// and zero-width formatters — everything a terminal control sequence needs.
/// It is also injective, so escaping both sides of the before/after untracked
/// comparison cannot make two distinct paths collide.
fn escape_path(path: &str) -> String {
    path.escape_debug().to_string()
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

/// Parse the output of `git diff --numstat -z --no-renames <sha>`.
///
/// With `-z`, records are NUL-terminated and paths are emitted **verbatim**
/// (git never quotes/C-escapes them), so spaces and non-ASCII survive intact —
/// and so do control bytes, which is why every path goes through
/// [`escape_path`] before it is stored.
/// Within a record the three fields are `<added>\t<deleted>\t<path>`; binary
/// files use `-` for the counts. `--no-renames` guarantees every record is a
/// plain path (no `old\0new` rename pair), so a rename surfaces honestly as a
/// deletion plus an addition. Pure function so the net-change computation is
/// unit-testable without invoking git.
pub fn parse_numstat(output: &str) -> Vec<NumStat> {
    output
        .split('\0')
        .filter_map(|record| {
            if record.is_empty() {
                return None; // trailing NUL yields an empty final record
            }
            let mut parts = record.splitn(3, '\t');
            let added = parts.next()?;
            let deleted = parts.next()?;
            let path = parts.next()?;
            if path.is_empty() {
                return None;
            }
            Some(NumStat {
                path: escape_path(path),
                added: added.parse::<u64>().ok(),
                deleted: deleted.parse::<u64>().ok(),
            })
        })
        .collect()
}

/// Parse the untracked (`??`) entries from `git status --porcelain -z -uall`.
///
/// With `-z`, entries are NUL-separated and paths are emitted **verbatim** (no
/// double-quoting/C-escaping), which hardens parsing for paths with spaces or
/// non-ASCII characters — and passes control bytes through just as faithfully,
/// so every path goes through [`escape_path`] before it is stored. Rename entries emit the old path as a separate NUL
/// field, but those never carry the `?? ` prefix, so filtering on it naturally
/// keeps only genuine untracked paths. Pure function — the before/after
/// untracked sets feed [`new_untracked`].
pub fn parse_untracked(porcelain: &str) -> BTreeSet<String> {
    porcelain
        .split('\0')
        .filter_map(|entry| entry.strip_prefix("?? "))
        .map(escape_path)
        .collect()
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
    /// The project directory is not a git repository (or git is unavailable) and
    /// nothing at all could be measured. Timing is still reported.
    Unavailable { duration: Duration, exit_code: u8 },
    /// A baseline commit existed, but a post-run git query **failed** — e.g. the
    /// agent ran `git gc --prune=now` (pinned SHA unreachable), deleted/renamed
    /// `.git`, corrupted the index, or git timed out. Net changes could NOT be
    /// measured. This is deliberately distinct from a clean "no changes" report:
    /// the audit must never affirm a clean session it was unable to verify.
    Incomplete { duration: Duration, exit_code: u8 },
    /// A change audit. When `tracked_audited` is true the changes were measured
    /// against the pinned baseline commit; when false there was no baseline
    /// commit (e.g. a fresh `git init`) and only NEW UNTRACKED files could be
    /// surfaced — tracked-change auditing is unavailable in that case.
    Available {
        duration: Duration,
        exit_code: u8,
        changes: Vec<FileChange>,
        total_added: u64,
        total_deleted: u64,
        /// True when tracked changes were diffed against a pinned baseline; false
        /// in the no-baseline case where only untracked additions are shown.
        tracked_audited: bool,
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
    /// Whether the pre-run `git status` actually SUCCEEDED. When it failed,
    /// `before_untracked` is an empty set that does NOT mean "no untracked
    /// files" — using it to compute the after−before delta would over-report
    /// every pre-existing untracked file as NEW. `finish` consults this to emit
    /// an honest `Incomplete` instead of false-positive "new" files.
    before_ok: bool,
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
        // Capture the pre-run untracked set REGARDLESS of whether a baseline
        // commit exists: in a fresh `git init` (no commits) we still want to
        // surface the files the agent creates during the session. Track whether
        // the query SUCCEEDED so `finish` never mistakes a failed capture (empty
        // set) for a genuinely empty untracked set and over-reports.
        let before_status = git_output(project_dir, &["status", "--porcelain", "-z", "-uall"]);
        let before_ok = before_status.is_some();
        let before_untracked = before_status
            .map(|s| parse_untracked(&s))
            .unwrap_or_default();
        Self {
            start,
            project_dir: project_dir.to_path_buf(),
            pinned_sha,
            before_untracked,
            before_ok,
        }
    }

    /// Generate the report after the agent exits. Diffs the current working tree
    /// against the pinned baseline SHA (capturing changes even if the agent
    /// committed or reset them) and computes net-new untracked files.
    ///
    /// `settled` states whether the session's process tree was known to have
    /// exited before this sample was taken (see [`SettleProbe`]). It is a
    /// required argument rather than an assumption because an unsettled session
    /// may still be writing: the sample is then a snapshot, not a verdict, and
    /// an empty one must never be rendered as a clean bill of health.
    pub fn finish(self, exit_code: u8, settled: bool) -> AuditReport {
        let duration = self.start.elapsed();

        // The after-untracked query. `None` means the git command FAILED (git
        // gone, corrupt repo, timeout) — genuinely distinct from `Some(empty)`
        // (git succeeded and reported no untracked files). We must never treat a
        // failure as "no changes".
        let after_untracked_opt =
            git_output(&self.project_dir, &["status", "--porcelain", "-z", "-uall"])
                .map(|s| parse_untracked(&s));

        // Guard against the over-report bias: if the BEFORE `git status` failed
        // yet the AFTER one succeeded, the repo plainly exists (after worked) but
        // `before_untracked` is an untrustworthy empty set. Computing after−before
        // would flag every pre-existing untracked file as NEW. We can't compute a
        // trustworthy untracked delta, so surface an honest `Incomplete` rather
        // than false positives. (If the after query ALSO failed we fall through:
        // the no-baseline path reports Unavailable, the baseline path Incomplete.)
        if !self.before_ok && after_untracked_opt.is_some() {
            return AuditReport::Incomplete {
                duration,
                exit_code,
            };
        }

        let Some(sha) = self.pinned_sha else {
            // No baseline commit (e.g. fresh `git init`). Tracked-change
            // auditing is unavailable, but we still surface NEW UNTRACKED files
            // the agent created so a bootstrap session isn't a blind spot.
            let Some(after_untracked) = after_untracked_opt else {
                // Even the untracked query failed → nothing measurable at all.
                return AuditReport::Unavailable {
                    duration,
                    exit_code,
                };
            };
            let new_files = new_untracked(&self.before_untracked, &after_untracked);
            if new_files.is_empty() {
                return AuditReport::Unavailable {
                    duration,
                    exit_code,
                };
            }
            let changes = new_files
                .into_iter()
                .map(|path| {
                    let sensitive = classify_path(&path);
                    FileChange {
                        path,
                        added: None,
                        deleted: None,
                        is_new_untracked: true,
                        sensitive,
                    }
                })
                .collect();
            return AuditReport::Available {
                duration,
                exit_code,
                changes,
                total_added: 0,
                total_deleted: 0,
                tracked_audited: false,
            };
        };

        // Net TRACKED changes vs the *pinned* commit — not moving HEAD.
        // `--no-renames` makes a rename surface as an explicit deletion +
        // addition; `-z` emits paths verbatim. A `None` here means the diff
        // command FAILED (e.g. the agent ran `git gc` and the pinned commit is
        // now unreachable, or the index is locked/corrupt, or git timed out).
        // Reporting that as an empty/clean audit would falsely affirm a clean
        // session we could not actually verify, so we surface it honestly as
        // Incomplete instead.
        let Some(tracked_out) = git_output(
            &self.project_dir,
            &["diff", "--numstat", "-z", "--no-renames", &sha],
        ) else {
            return AuditReport::Incomplete {
                duration,
                exit_code,
            };
        };
        let tracked = parse_numstat(&tracked_out);

        // Likewise, a failed after-untracked query with a valid baseline is an
        // incomplete audit — not a clean one.
        let Some(after_untracked) = after_untracked_opt else {
            return AuditReport::Incomplete {
                duration,
                exit_code,
            };
        };
        // Net NEW untracked files: after-untracked MINUS before-untracked.
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

        // GHSA-c47q-c3c8-7wrf: a session whose process tree never settled may
        // still be writing to the project. Finding nothing is then an absence of
        // information, not a clean session — the one thing this audit must never
        // affirm without having measured it. Changes we DID find are still worth
        // showing (with the caveat `run` prints); an empty sample is not.
        if !settled && changes.is_empty() {
            return AuditReport::Incomplete {
                duration,
                exit_code,
            };
        }

        AuditReport::Available {
            duration,
            exit_code,
            changes,
            total_added,
            total_deleted,
            tracked_audited: true,
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
                    "change audit unavailable: not a git repository, no commits yet, or git unavailable",
                );
            }
            AuditReport::Incomplete {
                duration,
                exit_code,
            } => {
                ui::info(&format!(
                    "Session ended (exit {exit_code}, {})",
                    human_duration(*duration)
                ));
                // Distinct, honest outcome: a baseline existed but git could not
                // measure the net changes. Never rendered as a clean session.
                ui::warn("audit incomplete, cplt could not verify project changes");
            }
            AuditReport::Available {
                duration,
                exit_code,
                changes,
                total_added,
                total_deleted,
                tracked_audited,
            } => {
                ui::info(&format!(
                    "Session ended (exit {exit_code}, {})",
                    human_duration(*duration)
                ));
                if !tracked_audited {
                    // No baseline commit: only untracked additions are shown.
                    ui::warn(
                        "tracked-change audit unavailable (no baseline commit); showing new untracked files only",
                    );
                }
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
/// failure (git missing, non-zero exit, timeout, non-UTF8). Never panics — git
/// absence or a hang must degrade cleanly.
///
/// The command comes from [`crate::git::command`], which is what keeps a
/// repository from choosing a program this — *unsandboxed, parent-side* —
/// process executes (issue #210). `GIT_OPTIONAL_LOCKS=0` comes from there too,
/// so read-only queries (`status`) never take the index lock. When that builder
/// refuses (the repo defines a content filter git would run) this returns
/// `None`, which the report turns into an honest `Incomplete` rather than a
/// false "clean session".
///
/// The call is bounded by [`GIT_TIMEOUT`]: the child is spawned, its stdout
/// drained on a helper thread (so a large diff can't fill the pipe buffer and
/// deadlock while we poll), and on timeout the child is killed and reaped (no
/// zombie) before returning `None`.
fn git_output(project_dir: &Path, args: &[&str]) -> Option<String> {
    let mut child = crate::git::command(project_dir, args)?
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Drain stdout on a helper thread so git can never block writing to a full
    // pipe while the main thread waits for it to exit.
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });

    let deadline = Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Timed out: kill and reap so we don't leak a zombie, then
                    // let the reader observe EOF and join.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return None;
            }
        }
    };

    // Child exited; its stdout write end is closed, so the reader hits EOF.
    let buf = reader.join().ok()?;
    if !status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Writable roots the audit does NOT measure: every `allow.write` grant that
/// falls outside `project_dir`.
///
/// The audit runs git in `project_dir` alone, so a session that only touched a
/// granted repository is reported as "no project file changes" — an absence of
/// information rendered as a clean bill of health (#214). Naming the roots
/// removes the false assurance; auditing them properly needs a per-root report
/// format and belongs with the multi-repo work in #165.
///
/// Paths *inside* `project_dir` are omitted: the project's own `git status`
/// already covers them. (A grant pointing at a git-ignored subdirectory is a
/// residual — git does not report those either, and this function cannot tell.)
fn unaudited_roots<'a>(project_dir: &Path, allow_write: &'a [PathBuf]) -> Vec<&'a Path> {
    allow_write
        .iter()
        .map(PathBuf::as_path)
        .filter(|p| !p.starts_with(project_dir))
        .collect()
}

/// The warning line naming the writable roots the audit did not measure, or
/// `None` when every grant sits inside the project.
///
/// SECURITY (GHSA-c47q-c3c8-7wrf): these paths do not come through
/// [`parse_numstat`]/[`parse_untracked`], so the parse-boundary escaping never
/// sees them — and they are no more cplt's own text than a git path is. An
/// `allow.write` grant can be written by the repository's own `.cplt.toml`, and
/// `project_dir` is a directory name the session may itself have created. Both
/// go through [`escape_path`] before reaching the terminal.
fn unaudited_warning(project_dir: &Path, unaudited: &[&Path]) -> Option<String> {
    if unaudited.is_empty() {
        return None;
    }
    let list = unaudited
        .iter()
        .map(|p| escape_path(&p.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "audit covers {} only — {} writable path{} outside it {} NOT audited: {list}",
        escape_path(&project_dir.display().to_string()),
        unaudited.len(),
        if unaudited.len() == 1 { "" } else { "s" },
        if unaudited.len() == 1 { "was" } else { "were" },
    ))
}

/// Detects processes that outlive the one cplt waits for.
///
/// SECURITY (GHSA-c47q-c3c8-7wrf): the closure [`run`] wraps returns when the
/// **direct** child is reaped, and a reaped direct child says nothing about the
/// rest of the tree. `cplt --yes exec -- /bin/sh -c '(sleep 1; printf late >
/// late.txt) &'` reaped the shell instantly; the audit sampled git and printed
/// "no project file changes" a full second before `late.txt` appeared. The
/// session got a clean bill of health for a write it had already scheduled.
///
/// The probe is a pipe. Its write end is deliberately left **without**
/// close-on-exec, so the sandboxed process and every process it forks inherit a
/// copy (and `seal_inherited_fds` re-clears the flag on it at exec time, so a
/// later change there cannot quietly seal it shut — see [`SETTLE_PROBE_FD`]);
/// cplt closes its own copy once the session has started. The read end
/// therefore reaches EOF exactly when the last process holding a copy is gone —
/// a wait for the whole tree that needs no process-group surgery.
///
/// Why not a process group: putting the session in its own group means it is no
/// longer the terminal's foreground group, so an interactive agent is stopped
/// by SIGTTIN the moment it reads stdin and by SIGTTOU when it sets raw mode
/// (which the agents cplt runs do — see `ignore_terminal_stop_signals`).
/// Getting that right needs `tcsetpgrp` handover in both parent and child, on
/// every spawn path, and buys no extra containment: `setsid` walks straight out
/// of a process group, and killing the group would also kill a background
/// process the user deliberately started.
///
/// This is a detector, not a cage. A descendant that closes the descriptor and
/// detaches is invisible from the parent — no parent-side mechanism can see it.
/// That is exactly why a failed settle degrades the **report** rather than
/// pretending to have contained anything: what cplt cannot establish, it says.
struct SettleProbe {
    read: libc::c_int,
    write: libc::c_int,
}

/// The armed probe's write end, or `-1`.
///
/// `sandbox_exec::seal_inherited_fds` makes every descriptor above stderr
/// close-on-exec so that whatever launched cplt cannot leak an open file past
/// the path rules (#329). The probe's write end is the one descriptor that must
/// survive `execve`, and it is the only one: it is a pipe cplt created, cplt
/// holds the only read end, and handing it to the session is the entire
/// mechanism. Published here rather than threaded through `exec` because the
/// seal is the single choke point all three spawn paths share — a fourth path
/// added later inherits the exemption instead of silently re-breaking the probe.
///
/// Missing this is silent and fails OPEN: a sealed write end is closed by
/// `execve`, the read end sees EOF at once, and every session reports itself
/// settled (GHSA-c47q-c3c8-7wrf).
pub(crate) static SETTLE_PROBE_FD: AtomicI32 = AtomicI32::new(-1);

impl SettleProbe {
    /// Arm the probe. Must be called **before** the session starts so every
    /// process it spawns inherits the write end. `None` when the pipe could not
    /// be created, which [`run`] treats as "settling could not be established".
    fn arm() -> Option<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a valid 2-element array; `pipe` writes both slots.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return None;
        }
        // Only the WRITE end may reach the session: the read end is cplt's
        // alone, so nothing in the sandbox can consume what it observes.
        // SAFETY: `fds[0]` is a descriptor `pipe` just returned.
        unsafe { libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) };
        // Exempt the write end from the exec-time seal, or nothing in the
        // session inherits it and the probe reports every session settled.
        SETTLE_PROBE_FD.store(fds[1], Ordering::Relaxed);
        Some(Self {
            read: fds[0],
            write: fds[1],
        })
    }

    /// Close cplt's own copy of the write end and wait for every inherited copy
    /// to close. `true` when the tree settled within [`SETTLE_TIMEOUT`].
    ///
    /// Consumes the probe: both descriptors are closed before returning.
    fn settled(self) -> bool {
        // Retract the exemption before the descriptor number is freed, so a
        // later spawn cannot un-seal whatever gets that number next.
        SETTLE_PROBE_FD.store(-1, Ordering::Relaxed);
        // Ours goes first — while cplt holds a write end, EOF can never fire.
        // SAFETY: `self.write` is owned by this probe and closed exactly once.
        unsafe { libc::close(self.write) };

        let deadline = Instant::now() + SETTLE_TIMEOUT;
        let outcome = loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pfd = libc::pollfd {
                fd: self.read,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid `pollfd`, matching count of 1.
            let ready =
                unsafe { libc::poll(&raw mut pfd, 1, remaining.as_millis() as libc::c_int) };
            if ready == 0 {
                break false; // deadline hit with the descriptor still held
            }
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break false;
            }
            // Readable or hung up. Only a zero-length read proves EOF: a hostile
            // descendant can WRITE to the descriptor it inherited, and taking
            // readability for EOF would hand it back the false clean.
            let mut buf = [0u8; 64];
            // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
            let n = unsafe { libc::read(self.read, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                break true; // every copy of the write end is closed
            }
            if n < 0
                && !matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                )
            {
                break false;
            }
        };

        // SAFETY: `self.read` is owned by this probe and closed exactly once.
        unsafe { libc::close(self.read) };
        outcome
    }
}

/// Wrap a sandboxed exec with the audit lifecycle: capture the baseline just
/// before the closure runs the agent, then generate and print the report after
/// it exits. Both `main.rs` exec sites call this so the wiring cannot diverge.
///
/// `allow_write` is the resolved set of writable grants; any of them outside
/// `project_dir` is named after the report so the session is never presented as
/// clean on the strength of a measurement that never looked there (#214).
///
/// When `enabled` is false (`--no-audit`, `--quiet`, or config `audit = false`)
/// the closure runs with no measurement or output at all.
pub fn run<F: FnOnce() -> u8>(
    project_dir: &Path,
    allow_write: &[PathBuf],
    enabled: bool,
    exec: F,
) -> u8 {
    if !enabled {
        return exec();
    }
    let baseline = Baseline::capture(project_dir);
    // Armed AFTER the baseline, so only the session's own processes inherit the
    // write end — the baseline's short-lived git children are already reaped.
    let probe = SettleProbe::arm();
    let exit_code = exec();
    // `exec` returns when the DIRECT child is reaped; the sample must not be
    // taken until the rest of the tree is gone too (GHSA-c47q-c3c8-7wrf).
    let settled = probe.is_some_and(SettleProbe::settled);
    baseline.finish(exit_code, settled).print();
    if !settled {
        // Emitted next to the report rather than inside `AuditReport`: it is
        // true of every variant and none of them has a place to put it.
        ui::warn(
            "the session left processes running — anything they change from here on is NOT audited",
        );
    }
    if let Some(line) = unaudited_warning(project_dir, &unaudited_roots(project_dir, allow_write)) {
        ui::warn(&line);
    }
    exit_code
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: no unsandboxed parent to protect (#239)
mod tests {
    use super::*;
    use std::process::Command;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(ToString::to_string).collect()
    }

    /// The forgery from GHSA-c47q-c3c8-7wrf, at byte level.
    ///
    /// git's `-z` output hands the path over verbatim, and the report is
    /// printed with bare `eprintln!`. A file NAMED with CR + erase-line +
    /// cursor-up + erase-line rewrote the "Project changes: 1 file" line above
    /// it with text of the session's choosing, so a session that wrote a file
    /// reported itself clean. Every control byte a terminal acts on must be
    /// gone from the parsed path: ESC, CSI, OSC, BEL, CR, LF, and the C1
    /// controls, which are two innocuous-looking UTF-8 bytes rather than one.
    #[test]
    fn parse_numstat_escapes_every_terminal_control_byte() {
        // CR, CSI erase-line, CSI cursor-up, OSC title change + BEL, raw C1
        // CSI (U+009B), and a newline that would forge a whole extra line.
        let hostile = "\r\u{1b}[2K\u{1b}[1A\u{1b}]0;pwned\u{7}\u{9b}2K\nfaked.txt";
        let rows = parse_numstat(&format!("1\t0\t{hostile}\0"));
        assert_eq!(rows.len(), 1, "one record: {rows:?}");
        let path = &rows[0].path;

        assert!(
            path.bytes().all(|b| (0x20..0x7f).contains(&b) || b >= 0x80),
            "a C0 control or DEL reached the report path: {path:?}"
        );
        assert!(
            !path.chars().any(char::is_control),
            "a control character reached the report path: {path:?}"
        );
        // Escaped, not stripped: the audit exists to show that something odd
        // was attempted, and a stripped payload reads as a typo.
        for evidence in ["\\r", "\\n", "\\u{1b}", "\\u{7}", "\\u{9b}"] {
            assert!(
                path.contains(evidence),
                "the attempt must survive as evidence ({evidence}): {path:?}"
            );
        }
    }

    /// The same path into the report, via `git status`: a file the session
    /// CREATES is the easier attack, since it needs no tracked file at all.
    #[test]
    fn parse_untracked_escapes_every_terminal_control_byte() {
        let hostile = "\r\u{1b}[2K\u{1b}[1A\u{1b}]0;pwned\u{7}\u{9b}2K\nfaked.txt";
        let paths = parse_untracked(&format!("?? {hostile}\0"));
        assert_eq!(paths.len(), 1, "one entry: {paths:?}");
        let path = paths.iter().next().unwrap();

        assert!(
            path.bytes().all(|b| (0x20..0x7f).contains(&b) || b >= 0x80),
            "a C0 control or DEL reached the report path: {path:?}"
        );
        assert!(
            !path.chars().any(char::is_control),
            "a control character reached the report path: {path:?}"
        );
        assert!(
            path.contains("\\u{1b}"),
            "the attempt must survive as evidence: {path:?}"
        );
    }

    /// The escaping is only acceptable because it is lossless for real names.
    /// `escape_default` would neutralise the attack just as well and turn every
    /// Norwegian, Japanese or accented filename into `\u{...}` noise in the one
    /// report the user reads to decide whether to trust the session — so the
    /// choice of `escape_debug` is pinned here, exactly as it is in the proxy.
    #[test]
    fn parsed_paths_keep_non_ascii_filenames_readable() {
        let names = [
            "src/høyre-kolonne.rs",
            "docs/naïve-café.md",
            "テスト/設定.toml",
            "sub dir/plain.txt",
        ];
        for name in names {
            let rows = parse_numstat(&format!("3\t1\t{name}\0"));
            assert_eq!(rows[0].path, name, "numstat mangled a legitimate name");
            let untracked = parse_untracked(&format!("?? {name}\0"));
            assert!(
                untracked.contains(name),
                "status mangled a legitimate name: {untracked:?}"
            );
        }
    }

    /// Escaping at the parse boundary must not cost the sensitive-file
    /// classification that runs on the same string: a hostile name still has to
    /// be flagged for what it is.
    ///
    /// This is the reason the layer is safe. `escape_debug` only ever inserts a
    /// `\\` in front of a character it escapes, and it escapes nothing that any
    /// entry in [`SENSITIVE_PATTERNS`] is made of — the literals are printable
    /// ASCII with no quotes, and `/` is neither escaped nor produced by an
    /// escape — so every `Name`/`Prefix`/`Suffix`/`Dir` match that held on the
    /// raw path still holds on the escaped one, and no escape sequence can
    /// synthesise a new match (`\\u{...}` emits no `.` and no capital letter).
    #[test]
    fn escaped_paths_are_still_classified() {
        let rows = parse_numstat("1\t0\t.github/workflows/\u{1b}[2Kci.yml\0");
        assert_eq!(classify_path(&rows[0].path), Some("CI/CD workflow"));
        let rows = parse_numstat("1\t0\tdeploy\u{7}.sh\0");
        assert_eq!(classify_path(&rows[0].path), Some("shell script"));

        // Quotes are the interesting case, because `escape_debug` escapes both
        // of them: `it's.env` becomes `it\'s.env`. A backslash landing next to
        // a matcher literal must not push the literal out of place, in any of
        // the four matcher shapes.
        for (path, reason) in [
            ("scripts/deploy's.sh", "shell script"),             // Suffix
            ("certs/it\"s.pem", "private key / credential"),     // Suffix, other quote
            (".env\"backup", "env file"),                        // Prefix
            ("it's/.github/workflows/ci.yml", "CI/CD workflow"), // Dir
            ("it's/Dockerfile", "container image"),              // Name
        ] {
            let rows = parse_numstat(&format!("1\t0\t{path}\0"));
            assert!(
                rows[0].path.contains('\\'),
                "test premise: the quote must actually have been escaped: {:?}",
                rows[0].path
            );
            assert_eq!(
                classify_path(&rows[0].path),
                Some(reason),
                "escaping a quote lost the classification of {path:?} ({:?})",
                rows[0].path
            );
        }
    }

    /// Hand the probe's write end to ONE child and to no one else.
    ///
    /// `arm` deliberately leaves the descriptor inheritable, which is exactly
    /// what makes it see the whole session tree in production, where `run` is
    /// the only thing that forks between arming and settling. This test binary
    /// runs hundreds of tests in parallel, so here the descriptor is hidden
    /// from every other test's children and un-hidden in this child alone.
    /// The descriptor number a probe-holding script sees.
    ///
    /// Fixed, and deliberately one digit: `/bin/sh` is dash on Debian, and dash
    /// parses only a single digit in `>&N` / `<&N`. The probe's own fd number
    /// depends on how many descriptors happen to be open, so a script written
    /// against it works while that number is below 10 and silently fails to
    /// parse above it — the redirection errors, the script produces no output,
    /// and the test fails somewhere unrelated. That is exactly what happened on
    /// Linux CI, and because the number varies it passed elsewhere.
    const SCRIPT_FD: i32 = 9;

    fn sh_holding_the_probe(probe: &SettleProbe, script: &str) -> Command {
        use std::os::unix::process::CommandExt as _;
        let fd = probe.write;
        // Keep the probe out of every OTHER child this test binary spawns:
        // tests run in parallel, and an unrelated process holding the write end
        // keeps the pipe open, which is precisely the "unsettled" condition
        // under test. Only the script below gets it, through the dup2 in
        // `pre_exec`, which clears FD_CLOEXEC on the copy it makes.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        // SAFETY: `dup2` is async-signal-safe and touches only these two
        // descriptors.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, SCRIPT_FD) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd
    }

    /// GHSA-c47q-c3c8-7wrf: reaping the direct child says nothing about the
    /// tree. `sh -c '(sleep 1; ...) &'` exits at once and the write lands a
    /// second later — the audit used to sample git in between and print a clean
    /// verdict for a write it had already been told about.
    #[test]
    fn settle_probe_waits_for_a_backgrounded_descendant() {
        let tmp = tempfile::tempdir().unwrap();
        let late = tmp.path().join("late.txt");
        let probe = SettleProbe::arm().expect("pipe");

        let status =
            sh_holding_the_probe(&probe, &format!("(sleep 1; : > '{}') &", late.display()))
                .status()
                .expect("sh runs");
        assert!(status.success());
        assert!(
            !late.exists(),
            "test premise: the direct child exits before the descendant writes"
        );

        assert!(probe.settled(), "the descendant's exit must be waited for");
        assert!(
            late.exists(),
            "settling returned before the write it exists to wait for"
        );
    }

    /// What cplt cannot establish, it must not claim. A descendant still
    /// running when the grace period expires is reported, not waited out
    /// forever and not killed — a background process the user deliberately
    /// started is theirs to keep.
    ///
    /// It also writes to the descriptor it inherited: taking mere READABILITY
    /// for EOF would hand the false clean straight back, so only a zero-length
    /// read counts as the tree having settled.
    #[test]
    fn settle_probe_reports_unsettled_while_a_descendant_lives() {
        let probe = SettleProbe::arm().expect("pipe");
        // The straggler's stdout goes to /dev/null, or `output()` would block
        // on the pipe until it exits and there would be nothing left to detect.
        let out = sh_holding_the_probe(
            &probe,
            &format!("sleep 5 >/dev/null 2>&1 & printf x >&{SCRIPT_FD}; echo $!"),
        )
        .output()
        .expect("sh runs");
        let pid: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();

        let started = Instant::now();
        let settled = probe.settled();
        let waited = started.elapsed();
        // SAFETY: `pid` is the child this test just started.
        unsafe { libc::kill(pid, libc::SIGKILL) };

        assert!(!settled, "a live descendant must never read as settled");
        // Slack for the sub-millisecond truncation in the poll timeout: the
        // point is that the grace was waited OUT, not returned from at once.
        assert!(
            waited >= SETTLE_TIMEOUT.saturating_sub(Duration::from_millis(50)),
            "the grace period must actually be waited out, got {waited:?}"
        );
    }

    /// The second terminal sink for text cplt does not control, and the one the
    /// parse-boundary escaping cannot reach: `allow.write` grants and the
    /// project directory name never pass through [`parse_numstat`] or
    /// [`parse_untracked`]. A grant can be written by the repository's own
    /// `.cplt.toml`, so the same forgery works here (GHSA-c47q-c3c8-7wrf).
    ///
    /// Asserted on BYTES: a `contains("\\u{1b}")` check alone passes just as
    /// happily on a line that ALSO still carries the raw ESC.
    #[test]
    fn unaudited_warning_escapes_every_terminal_control_byte() {
        let project = PathBuf::from("/w/app\u{1b}]0;pwned\u{7}");
        let roots = [
            PathBuf::from("/w/lib\r\u{1b}[2K\u{1b}[1A\u{1b}[2K[cplt] no project file changes"),
            PathBuf::from("/w/\u{9b}2K\nfaked"),
            PathBuf::from("/w/høyre-æøå"),
        ];
        let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let line = unaudited_warning(&project, &refs).expect("roots outside the project");

        let raw: Vec<u8> = line.bytes().filter(|b| *b < 0x20 || *b == 0x7f).collect();
        assert!(raw.is_empty(), "control bytes {raw:?} reached: {line:?}");
        // One warning in, one line out: the grant list cannot forge a second
        // `[cplt]`-prefixed line under the report.
        assert_eq!(line.lines().count(), 1, "line split: {line:?}");
        // Escaped, not stripped — the attempt is the evidence.
        for evidence in ["\\r", "\\n", "\\u{1b}", "\\u{7}", "\\u{9b}"] {
            assert!(
                line.contains(evidence),
                "the attempt must survive as evidence ({evidence}): {line:?}"
            );
        }
        // Lossless for legitimate names, the same reason `escape_debug` is the
        // primitive at the parse boundary.
        assert!(
            line.contains("/w/høyre-æøå"),
            "a legitimate non-ASCII grant was mangled: {line:?}"
        );
        assert!(unaudited_warning(&project, &[]).is_none());
    }

    #[test]
    fn unaudited_roots_names_grants_outside_the_project() {
        let project = PathBuf::from("/w/app");
        // Inside the project: the project's own git status already covers it.
        assert!(
            unaudited_roots(
                &project,
                &[PathBuf::from("/w/app/vendor"), PathBuf::from("/w/app")]
            )
            .is_empty()
        );
        // Outside: must be named, including a sibling that merely shares a prefix.
        assert_eq!(
            unaudited_roots(
                &project,
                &[
                    PathBuf::from("/w/app/vendor"),
                    PathBuf::from("/w/lib"),
                    PathBuf::from("/w/app-tools"),
                ]
            ),
            vec![Path::new("/w/lib"), Path::new("/w/app-tools")]
        );
        assert!(unaudited_roots(&project, &[]).is_empty());
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
        // `.lock`-suffixed lockfiles across ecosystems still match the suffix rule.
        assert_eq!(classify_path("composer.lock"), Some("dependency lockfile"));
        assert_eq!(classify_path("poetry.lock"), Some("dependency lockfile"));
        assert_eq!(classify_path("flake.lock"), Some("dependency lockfile"));
        // The npm family does NOT end in `.lock`, so each needs an explicit
        // exact-name matcher; without it, a package-lock.json supply-chain edit
        // would show WITHOUT the sensitive flag.
        assert_eq!(
            classify_path("package-lock.json"),
            Some("dependency lockfile")
        );
        assert_eq!(
            classify_path("frontend/package-lock.json"),
            Some("dependency lockfile")
        );
        assert_eq!(
            classify_path("npm-shrinkwrap.json"),
            Some("dependency lockfile")
        );
        assert_eq!(classify_path("pnpm-lock.yaml"), Some("dependency lockfile"));
        assert_eq!(classify_path("bun.lockb"), Some("dependency lockfile"));
    }

    #[test]
    fn classifier_flags_registry_credentials_ci_and_private_keys() {
        // Package-registry config (auth tokens / registry redirection).
        assert_eq!(
            classify_path(".npmrc"),
            Some("package registry credentials/config")
        );
        assert_eq!(
            classify_path(".pypirc"),
            Some("package registry credentials/config")
        );
        // Non-GitHub CI.
        assert_eq!(classify_path(".gitlab-ci.yml"), Some("CI/CD"));
        assert_eq!(classify_path("ci/Jenkinsfile"), Some("CI/CD"));
        // Private keys / SSH identities.
        assert_eq!(
            classify_path("certs/server.pem"),
            Some("private key / credential")
        );
        assert_eq!(
            classify_path("tls/private.key"),
            Some("private key / credential")
        );
        assert_eq!(
            classify_path(".ssh/id_rsa"),
            Some("private key / credential")
        );
        assert_eq!(
            classify_path("id_ed25519"),
            Some("private key / credential")
        );
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
        // `-z`: TAB between the three fields, NUL between records (trailing NUL).
        let out = "40\t2\tsrc/main.rs\x000\t10\tREADME.md\x00-\t-\tlogo.png\x00";
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

    /// FIX 4: under `-z` git emits paths verbatim, so a filename with a space
    /// round-trips without quoting/C-escaping mangling.
    #[test]
    fn parse_numstat_handles_spaced_path_under_z() {
        let out = "3\t1\tmy notes.txt\0";
        let parsed = parse_numstat(out);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].path, "my notes.txt");
        assert_eq!(parsed[0].added, Some(3));
        assert_eq!(parsed[0].deleted, Some(1));
    }

    /// FIX 3: a rename under `--no-renames` surfaces as a deletion (`+0 -N`) of
    /// the old path plus an addition of the new path — two plain records the
    /// parser handles independently.
    #[test]
    fn parse_numstat_rename_as_delete_plus_add() {
        // What `git diff --numstat -z --no-renames` emits for `old.txt`→`new.txt`.
        let out = "0\t2\told.txt\x002\t0\tnew.txt\x00";
        let parsed = parse_numstat(out);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, "old.txt");
        assert_eq!(parsed[0].added, Some(0));
        assert_eq!(parsed[0].deleted, Some(2));
        assert_eq!(parsed[1].path, "new.txt");
        assert_eq!(parsed[1].added, Some(2));
        assert_eq!(parsed[1].deleted, Some(0));
    }

    #[test]
    fn parse_untracked_extracts_question_entries() {
        // `-z`: entries NUL-separated; a rename emits its old path as a bare
        // trailing field ("app.rs") which lacks the `?? ` prefix and is dropped.
        let porcelain = " M src/main.rs\0R  renamed.rs\0app.rs\0?? new.txt\0?? sub/dir/x.sh\0";
        let untracked = parse_untracked(porcelain);
        assert_eq!(untracked, set(&["new.txt", "sub/dir/x.sh"]));
    }

    /// FIX 4: an untracked path containing a space round-trips verbatim under
    /// `-z` (no surrounding quotes to strip).
    #[test]
    fn parse_untracked_handles_spaced_path_under_z() {
        let porcelain = "?? my file.txt\0?? plain.rs\0";
        let untracked = parse_untracked(porcelain);
        assert_eq!(untracked, set(&["my file.txt", "plain.rs"]));
    }

    #[test]
    fn finish_reports_unavailable_without_baseline() {
        let base = Baseline {
            start: Instant::now(),
            project_dir: PathBuf::from("/nonexistent"),
            pinned_sha: None,
            before_untracked: BTreeSet::new(),
            before_ok: true,
        };
        match base.finish(0, true) {
            AuditReport::Unavailable { exit_code, .. } => assert_eq!(exit_code, 0),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    /// FIX 1 (honesty): a VALID baseline whose post-run diff FAILS must report
    /// `Incomplete`, never a clean/empty `Available`. Here the pinned SHA is
    /// non-empty but the project dir isn't a git repo, so `git diff <sha>`
    /// fails — the code must not silently treat that as "no changes".
    #[test]
    fn finish_reports_incomplete_when_diff_fails_with_valid_baseline() {
        let base = Baseline {
            start: Instant::now(),
            project_dir: PathBuf::from("/nonexistent"),
            pinned_sha: Some("deadbeef".to_string()),
            before_untracked: BTreeSet::new(),
            before_ok: true,
        };
        match base.finish(0, true) {
            AuditReport::Incomplete { exit_code, .. } => assert_eq!(exit_code, 0),
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    /// FIX 4 (over-report bias): when the BEFORE `git status` failed
    /// (`before_ok = false`) but the AFTER query succeeds in a real repo that
    /// has pre-existing untracked files, the code must NOT flag those as new.
    /// It cannot compute a trustworthy delta, so it reports `Incomplete` rather
    /// than an `Available` full of false-positive "new" files.
    #[test]
    fn finish_reports_incomplete_when_before_status_failed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ok = Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            eprintln!("skipping: git unavailable");
            return;
        }
        // A pre-existing untracked file the agent did NOT create.
        std::fs::write(dir.path().join("preexisting.txt"), b"x").unwrap();

        let base = Baseline {
            start: Instant::now(),
            project_dir: dir.path().to_path_buf(),
            // No baseline commit (fresh init); the after `git status` still works.
            pinned_sha: None,
            // Simulate a failed BEFORE capture: empty set, but NOT trustworthy.
            before_untracked: BTreeSet::new(),
            before_ok: false,
        };
        match base.finish(0, true) {
            AuditReport::Incomplete { exit_code, .. } => assert_eq!(exit_code, 0),
            other => panic!("expected Incomplete (untrustworthy delta), got {other:?}"),
        }
    }
}
