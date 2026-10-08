//! Record branch tracking that the sandbox could not, once the session ends.
//!
//! On macOS `.git/config` is write-denied, so the git gate strips `-u` from
//! `git push -u` and the upstream is never recorded (#402). The gate appends
//! `{cwd, argv}` for each stripped push to [`FILE`] in the session scratch dir.
//! After the session, the unsandboxed parent reads that file and writes
//! `branch.<b>.remote` and `branch.<b>.merge` for the entries that pass every
//! check here.
//!
//! The file is agent-writable, so every line is hostile input. This is the
//! first place the parent acts on output the gate wrote, and it writes only
//! those two keys, from values it re-derived or checked against the repository
//! itself. Anything else gets a copy-paste `git branch -u` line instead.

use std::collections::HashSet;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::config::GitGuardPolicy;
use crate::gh_proxy::{self, RepoFacts};

/// The tracking file, in the session scratch dir.
pub const FILE: &str = ".cplt-deferred-upstream.jsonl";

/// Read cap: a few hundred entries is already far past any real session.
const LIMIT: u64 = 64 * 1024;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Entry {
    cwd: String,
    argv: Vec<String>,
}

/// Gate side: append one entry. Best effort: a failure costs only the
/// session-end apply, and the in-session notice still says how to set it.
pub fn record(scratch: &Path, cwd: &Path, argv: &[String]) {
    let Ok(mut line) = serde_json::to_string(&Entry {
        cwd: cwd.to_string_lossy().into_owned(),
        argv: argv.to_vec(),
    }) else {
        return;
    };
    line.push('\n');
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(scratch.join(FILE))
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

/// An upstream that passed every check.
#[derive(Debug, PartialEq, Eq)]
pub struct Upstream {
    pub dir: PathBuf,
    pub remote: String,
    pub branch: String,
}

impl Upstream {
    /// Always the pushed branch's own name: `push <remote> <b>` writes
    /// `refs/heads/<b>` on the remote and nothing else.
    #[must_use]
    pub fn merge(&self) -> String {
        format!("refs/heads/{}", self.branch)
    }
}

/// Why an entry was not applied, with whatever safe names were known, so the
/// hint line can be filled in.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Skip {
    pub remote: Option<String>,
    pub branch: Option<String>,
}

impl Skip {
    #[must_use]
    pub fn hint(&self) -> String {
        let r = self.remote.as_deref().unwrap_or("<remote>");
        let b = self.branch.as_deref().unwrap_or("<branch>");
        format!("git branch -u {r}/{b} {b}")
    }
}

/// A name safe to put in a config key, a ref and a terminal line.
///
/// Narrower than git's ref rules on purpose: no `"`, `[`, `]`, whitespace or
/// control characters (config key and section syntax), no `@{` (`@{-1}` is
/// expanded by git), no `:` (a URL or a refspec), no leading `-`, `.` or `+` (a force push).
fn safe_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with(['-', '.', '+'])
        && !s.ends_with(['.', '/'])
        && !s.contains("..")
        && !s.contains("//")
        && !s.ends_with(".lock")
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '+' | '#'))
}

/// `push -u <remote> <branch|HEAD>` and nothing else: no global flags, no other
/// options, no refspec. Returns `(remote, target)`.
#[must_use]
pub fn parse(argv: &[String]) -> Option<(&str, &str)> {
    let (sub, rest) = argv.split_first()?;
    if sub != "push" {
        return None;
    }
    let mut set_upstream = 0;
    let mut pos = Vec::new();
    for a in rest {
        match a.as_str() {
            "-u" | "--set-upstream" => set_upstream += 1,
            _ if a.starts_with('-') => return None,
            _ => pos.push(a.as_str()),
        }
    }
    match (set_upstream, pos.as_slice()) {
        (1, [remote, target]) => Some((remote, target)),
        _ => None,
    }
}

/// What the parent found in the repository for one entry. Everything that needs
/// git is asked by the caller, so [`judge`] stays pure.
pub struct Probe<'a> {
    /// Canonical repository toplevel of the entry's cwd.
    pub toplevel: Option<&'a Path>,
    /// Canonical project dir and named roots.
    pub roots: &'a [PathBuf],
    /// The branch HEAD is on, if any.
    pub head: Option<&'a str>,
    /// `rev-parse --verify --end-of-options refs/heads/<b>` succeeded.
    pub branch_exists: &'a dyn Fn(&str) -> bool,
    /// `git remote` output.
    pub remotes: &'a [String],
    /// The git guard allows `push <remote> <b>`.
    pub push_allowed: &'a dyn Fn(&str, &str) -> bool,
}

/// Decide one entry. Every check is a reason to skip, never to guess.
pub fn judge(argv: &[String], p: &Probe) -> Result<Upstream, Skip> {
    let Some((remote, target)) = parse(argv) else {
        return Err(Skip::default());
    };
    let remote = safe_name(remote).then(|| remote.to_string());
    let branch = if target == "HEAD" {
        p.head.filter(|b| safe_name(b)).map(str::to_string)
    } else {
        safe_name(target).then(|| target.to_string())
    };
    let skip = || Skip {
        remote: remote.clone(),
        branch: branch.clone(),
    };
    let (Some(r), Some(b)) = (remote.as_deref(), branch.as_deref()) else {
        return Err(skip());
    };
    // Equal, not under: a nested clone inside a root is a different repository
    // that nobody named.
    let Some(dir) = p.toplevel.filter(|t| p.roots.iter().any(|root| root == t)) else {
        return Err(skip());
    };
    if !(p.branch_exists)(b) || !p.remotes.iter().any(|x| x == r) || !(p.push_allowed)(r, b) {
        return Err(skip());
    }
    Ok(Upstream {
        dir: dir.to_path_buf(),
        remote: r.to_string(),
        branch: b.to_string(),
    })
}

fn git_out(dir: &Path, args: &[&str]) -> Option<String> {
    let out = crate::git::command(dir, args)?.output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The entries in the tracking file. Empty for a missing, oversized,
/// symlinked or non-regular file; unparseable lines are dropped.
fn read_entries(path: &Path) -> Vec<Entry> {
    let Ok(Some(text)) = crate::untrusted::read_untrusted(path, LIMIT) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Write the two keys. Returns whether both writes succeeded.
fn write(u: &Upstream) -> bool {
    let set = |key: String, value: &str| {
        crate::git::command(&u.dir, &["config", "--local", &key, value])
            .and_then(|mut c| c.output().ok())
            .is_some_and(|o| o.status.success())
    };
    set(format!("branch.{}.remote", u.branch), &u.remote)
        && set(format!("branch.{}.merge", u.branch), &u.merge())
}

/// Probe the repository for one entry and judge it.
fn check(
    e: &Entry,
    roots: &[PathBuf],
    policy: &GitGuardPolicy,
    facts: &RepoFacts,
) -> Result<Upstream, Skip> {
    // Run no git in a directory outside the roots at all.
    let cwd = std::fs::canonicalize(&e.cwd)
        .ok()
        .filter(|c| roots.iter().any(|r| c.starts_with(r)));
    let toplevel = cwd
        .as_deref()
        .and_then(|c| git_out(c, &["rev-parse", "--show-toplevel"]))
        .and_then(|t| std::fs::canonicalize(t).ok());
    let dir = toplevel.clone().unwrap_or_default();
    let head = toplevel
        .as_ref()
        .and_then(|_| git_out(&dir, &["symbolic-ref", "--quiet", "--short", "HEAD"]));
    let remotes: Vec<String> = toplevel
        .as_ref()
        .and_then(|_| git_out(&dir, &["remote"]))
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default();
    let branch_exists = |b: &str| {
        let r = format!("refs/heads/{b}");
        git_out(
            &dir,
            &["rev-parse", "--verify", "--quiet", "--end-of-options", &r],
        )
        .is_some()
    };
    let push_allowed = |r: &str, b: &str| push_allowed(&dir, r, b, policy, facts);
    judge(
        &e.argv,
        &Probe {
            toplevel: toplevel.as_deref(),
            roots,
            head: head.as_deref(),
            branch_exists: &branch_exists,
            remotes: &remotes,
            push_allowed: &push_allowed,
        },
    )
}

/// The git guard's own verdict on `push <remote> <b>` in `dir`.
fn push_allowed(
    dir: &Path,
    remote: &str,
    branch: &str,
    policy: &GitGuardPolicy,
    facts: &RepoFacts,
) -> bool {
    let Some(git) = crate::git::trusted_git() else {
        return false;
    };
    let dir = dir.to_string_lossy();
    gh_proxy::gate_git(
        &["-C", &dir, "push", remote, branch],
        policy.prevent_push,
        policy.prevent_force_push,
        policy.protect_default_branch_only,
        &policy.allow_push,
        Some(git),
        facts,
    )
    .is_ok()
}

/// Parent side, after the session. `settled` is the audit's verdict; an
/// unsettled session may still be writing, so nothing is applied and every
/// entry gets a hint line instead.
pub fn apply(
    scratch: &Path,
    project_dir: &Path,
    repo_paths: &[PathBuf],
    policy: &GitGuardPolicy,
    settled: bool,
) {
    let entries = read_entries(&scratch.join(FILE));
    if entries.is_empty() {
        return;
    }
    let roots: Vec<PathBuf> = std::iter::once(project_dir)
        .chain(repo_paths.iter().map(PathBuf::as_path))
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    let ask_remote = policy.enabled && policy.protect_default_branch_only;
    let (facts, _) = gh_proxy::session_repo_facts(project_dir, repo_paths, ask_remote);
    let mut seen = HashSet::new();
    for e in &entries {
        let result = if settled {
            check(e, &roots, policy, &facts)
        } else {
            // Names only, for the hint; nothing is probed or written.
            judge(
                &e.argv,
                &Probe {
                    toplevel: None,
                    roots: &[],
                    head: None,
                    branch_exists: &|_| false,
                    remotes: &[],
                    push_allowed: &|_, _| false,
                },
            )
        };
        match result {
            Ok(u) if !seen.insert((u.dir.clone(), u.branch.clone())) => {}
            Ok(u) if write(&u) => crate::ui::info(&format!(
                "Recorded upstream {}/{} for branch {} in {}",
                u.remote,
                u.branch,
                u.branch,
                u.dir.display()
            )),
            Ok(u) => crate::ui::warn(&format!(
                "Could not record the upstream in {}. Run: {}",
                u.dir.display(),
                Skip {
                    remote: Some(u.remote),
                    branch: Some(u.branch)
                }
                .hint()
            )),
            Err(s) => {
                if seen.insert((PathBuf::new(), s.hint())) {
                    crate::ui::warn(&format!(
                        "A `git push -u` in the session did not record its upstream. \
                         In that repository, run: {}",
                        s.hint()
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test code: builds fixture repos
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_string).collect()
    }

    fn ok_probe<'a>(top: &'a Path, roots: &'a [PathBuf], remotes: &'a [String]) -> Probe<'a> {
        Probe {
            toplevel: Some(top),
            roots,
            head: Some("feat"),
            branch_exists: &|_| true,
            remotes,
            push_allowed: &|_, _| true,
        }
    }

    #[test]
    fn judge_accepts_named_branch_and_head() {
        let top = PathBuf::from("/r");
        let roots = [top.clone()];
        let remotes = vec!["origin".to_string()];
        let p = ok_probe(&top, &roots, &remotes);
        let u = judge(&argv("push -u origin feat"), &p).unwrap();
        assert_eq!((u.remote.as_str(), u.branch.as_str()), ("origin", "feat"));
        assert_eq!(u.merge(), "refs/heads/feat");
        assert_eq!(
            judge(&argv("push origin HEAD --set-upstream"), &p).unwrap(),
            u
        );
    }

    #[test]
    fn judge_refuses_repo_outside_or_under_a_root() {
        let roots = [PathBuf::from("/r")];
        let remotes = vec!["origin".to_string()];
        for top in ["/elsewhere", "/r/nested"] {
            let top = PathBuf::from(top);
            let p = ok_probe(&top, &roots, &remotes);
            assert!(judge(&argv("push -u origin feat"), &p).is_err(), "{top:?}");
        }
    }

    #[test]
    fn judge_refuses_hostile_branch_names() {
        let top = PathBuf::from("/r");
        let roots = [top.clone()];
        let remotes = vec!["origin".to_string()];
        let p = ok_probe(&top, &roots, &remotes);
        for b in [
            "a\nb",
            "x]\n[core",
            "[core]",
            "a\"b",
            "@{-1}",
            "-x",
            "a:b",
            "a b",
        ] {
            let args = vec!["push".into(), "-u".into(), "origin".into(), b.into()];
            assert!(judge(&args, &p).is_err(), "{b:?}");
        }
        // The same names arriving through HEAD.
        for head in ["a\"b", "x\n[core]"] {
            let p = Probe {
                head: Some(head),
                ..ok_probe(&top, &roots, &remotes)
            };
            assert!(judge(&argv("push -u origin HEAD"), &p).is_err(), "{head:?}");
        }
    }

    #[test]
    fn judge_refuses_unknown_remote_and_url() {
        let top = PathBuf::from("/r");
        let roots = [top.clone()];
        let remotes = vec!["origin".to_string()];
        let p = ok_probe(&top, &roots, &remotes);
        assert!(judge(&argv("push -u fork feat"), &p).is_err());
        assert!(judge(&argv("push -u https://evil.example/x.git feat"), &p).is_err());
        assert!(judge(&argv("push -u git@evil.example:x feat"), &p).is_err());
    }

    #[test]
    fn judge_refuses_other_forms() {
        let top = PathBuf::from("/r");
        let roots = [top.clone()];
        let remotes = vec!["origin".to_string()];
        let p = ok_probe(&top, &roots, &remotes);
        for a in [
            "push -u origin feat:other", // merge ref of a different name
            "push -u origin +feat",
            "push -u origin",
            "push origin feat",
            "push -u -u origin feat",
            "push -u --force origin feat",
            "branch -u origin/feat",
            "branch --set-upstream-to=origin/feat",
            "-C /x push -u origin feat",
        ] {
            assert!(judge(&argv(a), &p).is_err(), "{a}");
        }
    }

    #[test]
    fn judge_refuses_missing_branch_or_refused_push() {
        let top = PathBuf::from("/r");
        let roots = [top.clone()];
        let remotes = vec!["origin".to_string()];
        let p = Probe {
            branch_exists: &|_| false,
            ..ok_probe(&top, &roots, &remotes)
        };
        assert!(judge(&argv("push -u origin feat"), &p).is_err());
        let p = Probe {
            push_allowed: &|_, _| false,
            ..ok_probe(&top, &roots, &remotes)
        };
        let s = judge(&argv("push -u origin feat"), &p).unwrap_err();
        assert_eq!(s.hint(), "git branch -u origin/feat feat");
    }

    #[test]
    fn symlinked_tracking_file_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::write(&real, "{\"cwd\":\"/\",\"argv\":[\"push\"]}\n").unwrap();
        assert_eq!(read_entries(&real).len(), 1);
        let link = d.path().join(FILE);
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_entries(&link).is_empty());
        // The gate refuses to append through it, too.
        record(d.path(), Path::new("/"), &argv("push -u origin feat"));
        assert_eq!(read_entries(&real).len(), 1);
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let o = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap();
        assert!(
            o.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    /// A repo on branch `feat` with remote `origin`, whose default branch is `main`.
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let repo = std::fs::canonicalize(d.path()).unwrap().join("repo");
        std::fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-q", "-b", "main"]);
        git(
            &repo,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
        );
        git(
            &repo,
            &["remote", "add", "origin", "https://example.invalid/o/r.git"],
        );
        git(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
        git(
            &repo,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ],
        );
        git(&repo, &["checkout", "-q", "-b", "feat"]);
        (d, repo)
    }

    fn policy() -> GitGuardPolicy {
        GitGuardPolicy {
            enabled: true,
            prevent_push: true,
            protect_default_branch_only: true,
            ..GitGuardPolicy::default()
        }
    }

    #[test]
    fn apply_writes_exactly_two_keys() {
        let (_d, repo) = fixture();
        let scratch = tempfile::tempdir().unwrap();
        let before = git(&repo, &["config", "--local", "--list"]);
        record(scratch.path(), &repo, &argv("push -u origin HEAD"));
        apply(scratch.path(), &repo, &[], &policy(), true);
        let after = git(&repo, &["config", "--local", "--list"]);
        let added: Vec<&str> = after
            .lines()
            .filter(|l| !before.lines().any(|b| b == *l))
            .collect();
        assert_eq!(
            added,
            [
                "branch.feat.remote=origin",
                "branch.feat.merge=refs/heads/feat"
            ]
        );
        assert_eq!(after.lines().count(), before.lines().count() + 2);
    }

    #[test]
    fn apply_skips_protected_default_branch_and_unsettled_session() {
        let (_d, repo) = fixture();
        let scratch = tempfile::tempdir().unwrap();
        let before = git(&repo, &["config", "--local", "--list"]);
        record(scratch.path(), &repo, &argv("push -u origin main"));
        apply(scratch.path(), &repo, &[], &policy(), true);
        assert_eq!(git(&repo, &["config", "--local", "--list"]), before);

        let scratch = tempfile::tempdir().unwrap();
        record(scratch.path(), &repo, &argv("push -u origin feat"));
        apply(scratch.path(), &repo, &[], &policy(), false);
        assert_eq!(git(&repo, &["config", "--local", "--list"]), before);
    }

    #[test]
    fn apply_skips_nested_repo_under_root() {
        let (_d, repo) = fixture();
        let nested = repo.join("nested");
        std::fs::create_dir(&nested).unwrap();
        git(&nested, &["init", "-q", "-b", "feat"]);
        git(
            &nested,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            ],
        );
        git(
            &nested,
            &["remote", "add", "origin", "https://example.invalid/o/n.git"],
        );
        let before = git(&nested, &["config", "--local", "--list"]);
        let scratch = tempfile::tempdir().unwrap();
        record(scratch.path(), &nested, &argv("push -u origin feat"));
        apply(scratch.path(), &repo, &[], &policy(), true);
        assert_eq!(git(&nested, &["config", "--local", "--list"]), before);
    }
}
