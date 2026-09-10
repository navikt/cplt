//! Finding a repository on this machine from its `<owner>/<name>` identity.
//!
//! `cplt link navikt/sykepenger-model` is the whole of it today: the user names
//! a repository, cplt finds the checkout, verifies it really is that repository,
//! and writes the path into the per-checkout local config as a named root.
//!
//! The verification is the load-bearing part, and it is why this is a module
//! rather than three lines in `main`. A directory with a matching *name* is not
//! the repository: someone with `~/src/foo` unrelated to `navikt/foo` must not
//! have it linked, and a tree an earlier session could write is a tree whose
//! `.git/config` an earlier session could have pointed anywhere. So every
//! candidate has its origin read by the **trusted git in the unsandboxed
//! parent**, and the result must normalise to the identity asked for.
//!
//! What that verification is worth is bounded, and the bound is worth stating:
//! on Linux the agent can rewrite `.git/config` in any tree it was granted, and
//! Landlock cannot carve that file out of a writable root. "Origin verified" is
//! a statement about this moment, made parent-side. It is not a continuing
//! property of the linked tree — which is why the link is written as a path the
//! user is shown, and re-validated as a path on every launch, rather than
//! re-resolved from the identity each time.

use std::path::{Path, PathBuf};

/// How many sibling directories may have their origin read when no directory
/// name matched. Bounded because this is the only step that pays a git call per
/// directory rather than per candidate.
const ORIGIN_SCAN_LIMIT: usize = 50;

/// Where a candidate came from, for the line the user is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Beside the launch repository.
    Sibling,
    /// `<host>/<org>/<repo>`, the layout `~/go/src/github.com/navikt/cplt` has.
    SameForge,
    /// Name did not match; the origin did.
    RenamedClone,
    /// The user named the directory themselves.
    Named,
}

impl Found {
    /// How strong the evidence is. A directory named after the repository is
    /// evidence in itself; a directory matched only by the origin it claims is
    /// weaker, and there are usually several — every linked worktree of a
    /// repository reports the same origin, because they share one config.
    fn rank(self) -> u8 {
        match self {
            Self::Sibling | Self::Named => 0,
            Self::SameForge => 1,
            Self::RenamedClone => 2,
        }
    }

    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Sibling => "beside this repository",
            Self::SameForge => "under the same forge directory",
            Self::RenamedClone => "in a directory with a different name, matched by origin",
            Self::Named => "at the directory you named",
        }
    }
}

/// A verified checkout of the requested repository.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub dir: PathBuf,
    pub how: Found,
    /// Other *separate* checkouts that also verified as this repository — a
    /// different clone, not another worktree of this one. Reported, never
    /// silently discarded: one of them may be the one the user meant.
    pub also: Vec<Candidate>,
    /// How many linked worktrees of the chosen checkout were also matched.
    /// Counted rather than listed: they share one `.git`, so they all report
    /// the same origin, and a repository with thirty worktrees would otherwise
    /// print thirty lines that are all the same repository.
    pub worktrees: usize,
}

/// Why a resolution did not produce exactly one repository.
#[derive(Debug)]
pub enum ResolveError {
    /// The identity is not `<owner>/<name>`.
    BadIdentity(String),
    /// Nothing on this machine verified as that repository.
    NotFound {
        /// The paths tried by name, deduplicated.
        searched: Vec<PathBuf>,
        /// How many further directories had their origin read.
        scanned: usize,
    },
    /// More than one did. Never guessed between: one of them is the wrong tree,
    /// and the wrong tree is a project-grade write+exec grant.
    Ambiguous(Vec<Candidate>),
    /// No trusted git in the parent, so no origin can be read at all.
    NoTrustedGit,
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadIdentity(s) => write!(
                f,
                "{s:?} is not a repository identity. Name it as <owner>/<name>, \
                 for example navikt/cplt."
            ),
            Self::NotFound { searched, scanned } => {
                writeln!(f, "No checkout of that repository was found. Looked at:")?;
                for dir in searched {
                    writeln!(f, "  {}", dir.display())?;
                }
                if *scanned > 0 {
                    // The scan reads origins, so naming every directory would be
                    // a wall of paths that are not the answer.
                    writeln!(
                        f,
                        "  ...and the origin of {scanned} other director{} beside it",
                        if *scanned == 1 { "y" } else { "ies" }
                    )?;
                }
                write!(
                    f,
                    "Name the directory if it is somewhere else:\n  \
                     cplt link <owner>/<name> <dir>"
                )
            }
            Self::Ambiguous(found) => {
                writeln!(
                    f,
                    "More than one checkout claims to be that repository, so cplt is not \
                     picking one:"
                )?;
                for c in found {
                    writeln!(f, "  {} ({})", c.dir.display(), c.how.describe())?;
                }
                write!(
                    f,
                    "Name the one you mean:\n  cplt link <owner>/<name> <dir>"
                )
            }
            Self::NoTrustedGit => write!(
                f,
                "No trusted git binary in the parent environment, so no repository's \
                 identity can be verified. Name the directory instead:\n  \
                 cplt link <owner>/<name> <dir>"
            ),
        }
    }
}

/// Whether `identity` is a `<owner>/<name>` this may be used to build paths from.
///
/// The identity reaches path construction — `<parent>/<name>` — and in the
/// proposal form of this feature (#491) it is text a repository's committed
/// config chose. `..` and `/` in the wrong places would have cplt run git in a
/// directory of that file's choosing and print the path back to the operator.
#[must_use]
pub fn is_valid_identity(identity: &str) -> bool {
    let mut parts = identity.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    [owner, name].iter().all(|part| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    })
}

/// The `<owner>/<name>` a checkout's origin says it is, read parent-side.
fn identity_of(real_git: &Path, dir: &Path) -> Option<String> {
    crate::gh_proxy::detect_current_repo(real_git, dir).ok()
}

/// The `.git` a checkout shares with its linked worktrees, canonicalized.
///
/// Two directories with the same one are the same repository seen twice, not
/// two clones — and every worktree reports the repository's origin, since the
/// config lives in the shared directory.
fn common_dir(dir: &Path) -> Option<PathBuf> {
    crate::git::command(dir, &["rev-parse", "--git-common-dir"])
        .and_then(|mut c| c.output().ok())
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|p| std::fs::canonicalize(dir.join(p.trim())).ok())
}

/// Whether `dir` is a git toplevel — the directory itself, not somewhere inside
/// a repository.
fn is_toplevel(dir: &Path) -> bool {
    crate::git::command(dir, &["rev-parse", "--show-toplevel"])
        .and_then(|mut c| c.output().ok())
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|top| std::fs::canonicalize(top.trim()).ok())
        .is_some_and(|top| top == dir)
}

/// Verify one directory really is `identity`, and return it if so.
fn verify(real_git: &Path, dir: &Path, identity: &str, how: Found) -> Option<Candidate> {
    let dir = std::fs::canonicalize(dir).ok()?;
    if !is_toplevel(&dir) {
        return None;
    }
    let found = identity_of(real_git, &dir)?;
    crate::gh_proxy::repos_match(&found, identity).then_some(Candidate {
        dir,
        how,
        also: Vec::new(),
        worktrees: 0,
    })
}

/// Directories to try by name, in the order they are tried.
///
/// Not "everywhere under `$HOME`": a scan that wide is slow, surprising, and
/// reads trees the user never associated with this project.
fn name_candidates(project_dir: &Path, identity: &str) -> Vec<(PathBuf, Found)> {
    let (owner, name) = identity.split_once('/').unwrap_or(("", identity));
    let mut out = Vec::new();

    if let Some(parent) = project_dir.parent() {
        out.push((parent.join(name), Found::Sibling));
        // `<host>/<org>/<repo>`: the Go layout, and anyone who mirrors it. The
        // grandparent is the forge directory, so a repository in another org is
        // one directory across rather than nowhere.
        if let Some(forge) = parent.parent() {
            out.push((forge.join(owner).join(name), Found::SameForge));
        }
    }

    out
}

/// Sibling directories whose origin is worth reading when no name matched.
fn origin_scan_dirs(project_dir: &Path, home: &Path) -> Vec<PathBuf> {
    let Some(parent) = project_dir.parent() else {
        return Vec::new();
    };
    // A parent that is `$HOME` (or another unsafe root) would turn this into the
    // broad home scan this deliberately is not.
    if crate::is_unsafe_root(parent, home) {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && p != project_dir)
        .collect();
    dirs.sort();
    dirs.truncate(ORIGIN_SCAN_LIMIT);
    dirs
}

/// Find the one checkout of `identity` on this machine.
///
/// Every candidate from every step is collected before a verdict, rather than
/// stopping at the first hit: with stop-at-first, a tree that verifies at an
/// early step silently beats the real repository at a later one, and one of the
/// two is a write+exec grant over the wrong directory.
///
/// # Errors
/// See [`ResolveError`]: a malformed identity, nothing found, more than one
/// found, or no trusted git to verify with.
pub fn resolve(project_dir: &Path, home: &Path, identity: &str) -> Result<Candidate, ResolveError> {
    if !is_valid_identity(identity) {
        return Err(ResolveError::BadIdentity(identity.to_string()));
    }
    let Some(real_git) = crate::git::trusted_git() else {
        return Err(ResolveError::NoTrustedGit);
    };

    let by_name = name_candidates(project_dir, identity);
    // The sibling and same-forge paths coincide when the launch repository is in
    // the proposed owner's directory, and a path listed twice reads as two
    // places having been tried.
    let mut searched: Vec<PathBuf> = by_name.iter().map(|(p, _)| p.clone()).collect();
    searched.dedup();
    let mut scanned = 0usize;
    let mut found: Vec<Candidate> = Vec::new();

    for (dir, how) in by_name {
        // A candidate inside the launch repository is refused, not verified: that
        // tree is agent-writable, so a checkout planted there last session would
        // be a repository of the agent's choosing wearing the right name.
        if dir.starts_with(project_dir) {
            continue;
        }
        if let Some(c) = verify(real_git, &dir, identity, how) {
            found.push(c);
        }
    }

    // Always, not only when the name search came up empty. Stopping early would
    // let a decoy with the right *name* silently beat the real checkout in a
    // differently-named directory — and one of those two is a write+exec grant
    // over the wrong tree. This costs one `git config` per sibling directory,
    // capped, on a command a person runs by hand.
    for dir in origin_scan_dirs(project_dir, home) {
        if dir.starts_with(project_dir) {
            continue;
        }
        scanned += 1;
        if let Some(c) = verify(real_git, &dir, identity, Found::RenamedClone) {
            found.push(c);
        }
    }

    // A sibling matched by name is also reached by the scan; the same directory
    // twice is one candidate, not an ambiguity.
    found.sort_by(|a, b| a.dir.cmp(&b.dir));
    found.dedup_by(|a, b| a.dir == b.dir);

    if found.is_empty() {
        return Err(ResolveError::NotFound { searched, scanned });
    }

    // Ambiguity is refused only among equally good matches. Two directories
    // *named* after the repository are a genuine "which one did you mean";
    // a named one plus three that merely claim the same origin is the ordinary
    // shape of a repository with linked worktrees, and refusing that would make
    // the command unusable for anyone who uses them.
    //
    // The weaker matches are printed rather than dropped, because the ranking is
    // a heuristic and the operator is the one who knows.
    let best = found.iter().map(|c| c.how.rank()).min().unwrap_or(0);
    let (mut top, rest): (Vec<Candidate>, Vec<Candidate>) =
        found.into_iter().partition(|c| c.how.rank() == best);

    if top.len() > 1 {
        top.extend(rest);
        return Err(ResolveError::Ambiguous(top));
    }
    let mut winner = top.remove(0);
    let shared = common_dir(&winner.dir);
    let (mine, others): (Vec<Candidate>, Vec<Candidate>) = rest
        .into_iter()
        .partition(|c| shared.is_some() && common_dir(&c.dir) == shared);
    winner.worktrees = mine.len();
    winner.also = others;
    Ok(winner)
}

/// Verify a directory the user named themselves.
///
/// The path is theirs, so it is not searched for — but it is still checked
/// against the identity, because "I meant this one" and "this one is that
/// repository" are different claims and only the second makes the link mean
/// what it says.
///
/// # Errors
/// If no trusted git is available, or the directory is not that repository.
pub fn verify_named(dir: &Path, identity: &str) -> Result<Candidate, String> {
    if !is_valid_identity(identity) {
        return Err(ResolveError::BadIdentity(identity.to_string()).to_string());
    }
    let real_git =
        crate::git::trusted_git().ok_or_else(|| ResolveError::NoTrustedGit.to_string())?;
    let canonical =
        std::fs::canonicalize(dir).map_err(|e| format!("Cannot resolve {}: {e}", dir.display()))?;
    if !is_toplevel(&canonical) {
        return Err(format!(
            "{} is not the toplevel of a git repository.",
            canonical.display()
        ));
    }
    match identity_of(real_git, &canonical) {
        Some(found) if crate::gh_proxy::repos_match(&found, identity) => Ok(Candidate {
            dir: canonical,
            how: Found::Named,
            also: Vec::new(),
            worktrees: 0,
        }),
        Some(found) => Err(format!(
            "{} is {found}, not {identity}.\n  \
             Link it as itself if that is what you meant:\n    cplt link {found}",
            canonical.display()
        )),
        None => Err(format!(
            "Could not read a GitHub origin for {}, so cplt cannot confirm it is {identity}.\n  \
             A fork, a repository with no `origin`, or a non-GitHub remote all look like this.",
            canonical.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A repository at `dir` whose origin is `identity`, using the real git so
    /// the tests exercise the same reader the resolver does.
    #[allow(clippy::disallowed_methods)] // test fixture: PATH is the harness's, not an agent's
    fn make_repo(dir: &Path, identity: &str) {
        std::fs::create_dir_all(dir).expect("mkdir");
        let url = format!("git@github.com:{identity}.git");
        for args in [
            vec!["init", "-q"],
            vec!["remote", "add", "origin", url.as_str()],
        ] {
            let ok = std::process::Command::new("git")
                .args(&args)
                .current_dir(dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("git runs")
                .success();
            assert!(ok, "git {args:?} failed");
        }
    }

    /// Run git in `dir`, asserting success.
    #[allow(clippy::disallowed_methods)] // test fixture: PATH is the harness's, not an agent's
    fn git_in(dir: &Path, args: &[&str]) {
        let ok = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@e.x")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@e.x")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("git runs")
            .success();
        assert!(ok, "git {args:?} failed");
    }

    /// The identity reaches path construction, and in #491 it is text a
    /// repository's committed config chose. `..` there would have cplt run git
    /// in a directory that file picked and print the path to the operator.
    #[test]
    fn an_identity_that_is_not_owner_slash_name_is_refused() {
        for good in ["navikt/cplt", "nais/unleash", "a/b", "org.x/repo-1_2"] {
            assert!(is_valid_identity(good), "{good} should be accepted");
        }
        for bad in [
            "../../etc",
            "navikt/../../etc",
            "navikt",
            "navikt/cplt/extra",
            "/navikt/cplt",
            "navikt/",
            "",
            "..",
            "nav ikt/cplt",
            "navikt/./cplt",
        ] {
            assert!(!is_valid_identity(bad), "{bad:?} must be refused");
        }
    }

    /// The everyday case: the repository next door.
    #[test]
    fn a_sibling_is_found_and_its_origin_checked() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        make_repo(&root.join("sykepenger-model"), "navikt/sykepenger-model");

        let found = resolve(&project, &root, "navikt/sykepenger-model").expect("resolves");
        assert_eq!(found.dir, root.join("sykepenger-model"));
        assert_eq!(found.how, Found::Sibling);
    }

    /// A directory with the right name and a different origin is NOT the
    /// repository. Without this check, `~/src/foo` unrelated to `navikt/foo`
    /// becomes a write+exec grant over the wrong tree.
    #[test]
    fn a_matching_name_with_a_different_origin_is_not_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        make_repo(
            &root.join("sykepenger-model"),
            "someone-else/sykepenger-model",
        );

        let err = resolve(&project, &root, "navikt/sykepenger-model").expect_err("must refuse");
        assert!(matches!(err, ResolveError::NotFound { .. }), "{err}");
    }

    /// `<host>/<org>/<repo>`: a repository in another organisation is one
    /// directory across, not nowhere.
    #[test]
    fn a_repository_in_another_org_is_found_across_the_forge_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let forge = tmp
            .path()
            .canonicalize()
            .expect("canonical")
            .join("github.com");
        let project = forge.join("navikt").join("cplt");
        make_repo(&project, "navikt/cplt");
        make_repo(&forge.join("nais").join("unleash"), "nais/unleash");

        let found = resolve(&project, tmp.path(), "nais/unleash").expect("resolves");
        assert_eq!(found.dir, forge.join("nais").join("unleash"));
        assert_eq!(found.how, Found::SameForge);
    }

    /// A clone in a differently-named directory is still findable, by origin.
    #[test]
    fn a_renamed_clone_is_matched_by_its_origin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        make_repo(&root.join("model-wip"), "navikt/sykepenger-model");

        // A home elsewhere: the origin scan is skipped when the directory it
        // would read is the home directory itself.
        let found =
            resolve(&project, &root.join("home"), "navikt/sykepenger-model").expect("resolves");
        assert_eq!(found.dir, root.join("model-wip"));
        assert_eq!(found.how, Found::RenamedClone);
    }

    /// Two trees with equally good claims: one of them is the wrong tree, and
    /// the wrong tree is a project-grade write+exec grant. Refused, never
    /// guessed between.
    #[test]
    fn equally_good_candidates_are_refused_rather_than_picked_between() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        // Neither is named after the repository, so neither claim is stronger.
        make_repo(&root.join("model-wip"), "navikt/sykepenger-model");
        make_repo(&root.join("model-old"), "navikt/sykepenger-model");

        let err = resolve(&project, &root.join("home"), "navikt/sykepenger-model")
            .expect_err("must refuse");
        match err {
            ResolveError::Ambiguous(found) => assert_eq!(found.len(), 2, "{found:?}"),
            other => panic!("expected an ambiguity refusal, got {other}"),
        }
    }

    /// A directory *named* after the repository is evidence a directory that
    /// merely claims the same origin does not have. The weaker match is
    /// reported rather than dropped — the ranking is a heuristic, and a user
    /// with a decoy beside their checkout should be told it is there.
    #[test]
    fn a_weaker_match_does_not_block_the_link_but_is_reported() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        make_repo(&root.join("sykepenger-model"), "navikt/sykepenger-model");
        make_repo(&root.join("decoy"), "navikt/sykepenger-model");

        let found = resolve(&project, &root.join("home"), "navikt/sykepenger-model")
            .expect("the named one wins");
        assert_eq!(found.dir, root.join("sykepenger-model"));
        assert_eq!(
            found.also.iter().map(|c| &c.dir).collect::<Vec<_>>(),
            vec![&root.join("decoy")],
            "the other claim must be shown, not swallowed"
        );
    }

    /// Every linked worktree shares one config, so they all report the same
    /// origin. Counting them keeps `cplt link` usable for anyone who uses
    /// worktrees, without pretending they are separate clones.
    #[test]
    fn worktrees_of_the_chosen_checkout_are_counted_not_listed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        let model = root.join("sykepenger-model");
        make_repo(&model, "navikt/sykepenger-model");
        // A worktree needs a commit to branch from.
        std::fs::write(model.join("seed"), "x").expect("seed");
        git_in(&model, &["add", "seed"]);
        git_in(&model, &["commit", "-qm", "init"]);
        git_in(
            &model,
            &[
                "worktree",
                "add",
                "-q",
                root.join("model-hotfix").to_str().expect("utf8"),
                "-b",
                "hotfix",
            ],
        );

        let found = resolve(&project, &root.join("home"), "navikt/sykepenger-model")
            .expect("the main checkout wins");
        assert_eq!(found.dir, model);
        assert_eq!(found.worktrees, 1, "the worktree is counted");
        assert!(found.also.is_empty(), "and not reported as another clone");
    }

    /// The launch repository is agent-writable, so a checkout planted inside it
    /// is a repository of the agent's choosing wearing the right name.
    #[test]
    fn a_candidate_inside_the_launch_repository_is_never_taken() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let project = root.join("spleis");
        make_repo(&project, "navikt/spleis");
        make_repo(&project.join("sykepenger-model"), "navikt/sykepenger-model");

        let err = resolve(&project, &root, "navikt/sykepenger-model").expect_err("must refuse");
        assert!(matches!(err, ResolveError::NotFound { .. }), "{err}");
    }

    /// A directory the user named is still checked: "I meant this one" and
    /// "this one is that repository" are different claims.
    #[test]
    fn a_named_directory_is_verified_too() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().canonicalize().expect("canonical");
        let other = root.join("something-else");
        make_repo(&other, "someone-else/thing");

        let err = verify_named(&other, "navikt/sykepenger-model").expect_err("must refuse");
        assert!(
            err.contains("someone-else/thing"),
            "the error must name what it actually is: {err}"
        );
        verify_named(&other, "someone-else/thing").expect("its own identity verifies");
    }
}
