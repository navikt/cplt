//! Golden-path tests: the **operator's** view of cplt (#431).
//!
//! The rest of the e2e suite asserts on the agent's view of the sandbox — that
//! `~/.ssh` is unreadable, that a push is refused. Five defects in one week
//! passed every one of those tests because the values were right and the
//! visible surface was wrong or missing: `config show` reported both guards
//! disabled while they were enforcing (#410), an applied per-repo local file
//! left no trace anywhere, `config set --local sandbox.repo_dirs /nonexistent`
//! succeeded and bricked every later launch.
//!
//! Every test here runs the real binary against a scratch `HOME` and asserts on
//! what a human would have read: the launch summary on stderr, `config show`,
//! `config get`. The agent is `/usr/bin/true`, so there is no network, no
//! Docker, no browser and no timing budget — this file is meant to be a
//! required check.

// This turns off the #239 *security* lint only: a test binary is not the
// unsandboxed parent around an agent session, so the PATH-hijack hazard
// `disallowed_methods` guards against does not apply here. It grants no
// licence to spawn ad hoc: the #245 isolation rule stands unchanged, and every
// `Command` a test spawns is still built through the `tests/common` helpers,
// which no lint can enforce and review does.
#![allow(clippy::disallowed_methods)]
mod common;

use common::{bare_origin_repo, launch, make_config_home, temp_repo};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The agent every launch here runs: present on macOS and Linux, exits 0, and
/// does nothing observable, so the only thing under test is what cplt printed
/// on the way in.
const TRUE_BIN: &str = "/usr/bin/true";

/// `cplt exec` with the summary on: `--no-quiet` is what makes the guard lines
/// and the `Local:` line appear at all.
const LAUNCH: &[&str] = &["--no-quiet", "--yes", "--no-validate", "exec", "--"];

fn launch_agent(home: &Path, repo: &Path) -> (String, String, bool) {
    let mut args = LAUNCH.to_vec();
    args.push(TRUE_BIN);
    let (stdout, stderr, status) = launch(home, repo, &args);
    (stdout, stderr, status.success())
}

/// When `CPLT_TEST_REQUIRE_SANDBOX=1` is set (CI), a missing sandbox capability
/// must FAIL rather than silently skip — same contract as `require_sandbox!` in
/// `e2e.rs` and `require_landlock!` in `integration_linux.rs`.
fn require_sandbox_enforced() -> bool {
    std::env::var("CPLT_TEST_REQUIRE_SANDBOX").as_deref() == Ok("1")
}

/// Can a launch run here at all?
///
/// Probed by doing one, rather than by asking the platform: these tests care
/// about the whole path from config to summary, and a probe of `sandbox-exec`
/// or the Landlock ABI would answer a different question on each OS. Probed
/// once per test binary — the result cannot change mid-run.
fn launchable() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        let home = make_config_home("golden-probe");
        let repo = temp_repo("navikt/probe");
        let (_, stderr, ok) = launch_agent(&home, repo.path());
        if !ok {
            eprintln!("golden-path probe launch failed:\n{stderr}");
        }
        let _ = std::fs::remove_dir_all(&home);
        ok
    })
}

macro_rules! require_launch {
    () => {
        if !launchable() {
            assert!(
                !require_sandbox_enforced(),
                "a launch is required by CPLT_TEST_REQUIRE_SANDBOX but `cplt exec` failed here"
            );
            eprintln!("SKIPPED: `cplt exec` cannot run in this environment");
            return;
        }
    };
}

// ── Reading `config show` ────────────────────────────────────────────

/// The value `config show` prints for `section.key`, with the `[cplt]` prefix
/// and the column padding stripped, e.g. `true (default)` or `8443 (local)`.
///
/// Section-scoped on purpose: `enabled` and `mode` appear under both guards,
/// and #410 was precisely a case of one section's truth being read for the
/// other's.
fn shown(show: &str, section: &str, key: &str) -> String {
    let mut in_section = false;
    for raw in show.lines() {
        let line = raw.strip_prefix("[cplt]").unwrap_or(raw).trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line == format!("[{section}]");
            continue;
        }
        if !in_section {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            return value.trim().to_string();
        }
    }
    panic!("`config show` printed no {section}.{key}:\n{show}");
}

/// `cplt config show`, as the operator sees it (both streams: the header and
/// the values are `ui::info`, which writes to stderr).
fn config_show(home: &Path, repo: &Path) -> String {
    let (stdout, stderr, status) = launch(home, repo, &["config", "show"]);
    assert!(status.success(), "config show should succeed:\n{stderr}");
    format!("{stdout}{stderr}")
}

// ════════════════════════════════════════════════════════════════════
// Path 1 — the truth table: what the launch says, `config show` must say
// ════════════════════════════════════════════════════════════════════

/// #410: `config show` reported `gh_guard.enabled = false` and
/// `git_guard.enabled = false` while both guards were enforcing, and the git
/// guard's default was `warn` in one place and `block` in another. Nothing in
/// the suite compared the two surfaces, because nothing read either.
#[test]
fn golden_empty_config_launch_and_show_agree_the_guards_are_on() {
    require_launch!();
    let home = make_config_home("golden-truth-default");
    let repo = temp_repo("navikt/spleis");

    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "a default launch must succeed:\n{stderr}");

    assert!(
        stderr.contains("Command guards:"),
        "the summary must have a guard block when the guards are on:\n{stderr}"
    );
    assert!(
        stderr.contains("gh guard:      on"),
        "the summary must say the gh guard is on:\n{stderr}"
    );
    assert!(
        stderr.contains("git guard:     on"),
        "the summary must say the git guard is on:\n{stderr}"
    );
    // The warn/block drift: a guard running in warn mode is a guard that stops
    // nothing, and the marker is the only thing on this surface that says so.
    assert!(
        !stderr.contains("WARN MODE") && !stderr.contains("AUDIT MODE"),
        "the default is block mode, so no degraded-mode marker may appear:\n{stderr}"
    );

    let show = config_show(&home, repo.path());
    for section in ["gh_guard", "git_guard"] {
        assert_eq!(
            shown(&show, section, "enabled"),
            "true (default)",
            "`config show` must agree with the launch about {section}.enabled:\n{show}"
        );
        assert_eq!(
            shown(&show, section, "mode"),
            "block (default)",
            "`config show` must agree with the launch about {section}.mode:\n{show}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

/// The other half of the table. A preset that turns the guards off must turn
/// them off on *both* surfaces — the inverse of #410 is just as bad: an
/// operator who reads "on" and is not protected.
#[test]
fn golden_permissive_preset_launch_and_show_agree_the_guards_are_off() {
    require_launch!();
    let home = make_config_home("golden-truth-permissive");
    let repo = temp_repo("navikt/spleis");

    let (_, stderr, status) = launch(
        &home,
        repo.path(),
        &["config", "set", "sandbox.preset", "permissive", "--force"],
    );
    assert!(
        status.success(),
        "setting the preset should succeed:\n{stderr}"
    );

    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "a permissive launch must succeed:\n{stderr}");
    assert!(
        stderr.contains("Preset:        permissive"),
        "the summary must name the preset in force:\n{stderr}"
    );
    assert!(
        !stderr.contains("gh guard:") && !stderr.contains("git guard:"),
        "no guard may be reported on when the preset turned both off:\n{stderr}"
    );

    let show = config_show(&home, repo.path());
    for section in ["gh_guard", "git_guard"] {
        assert!(
            shown(&show, section, "enabled").starts_with("false"),
            "`config show` must agree with the launch that {section} is off:\n{show}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

/// The negative assertion in the default test — "no degraded-mode marker" —
/// protects nothing on its own: delete the marker from the summary and it
/// still passes, and the gate would then be pinning the absence of a string
/// that no longer exists. This is the positive half. It is also the surface
/// the git-guard drift lived on: a guard in warn mode stops nothing, and this
/// line is the only place the operator is told.
#[test]
fn golden_warn_mode_is_marked_on_the_summary() {
    require_launch!();
    let home = make_config_home("golden-warn");
    let repo = temp_repo("navikt/spleis");

    for guard in ["gh_guard", "git_guard"] {
        let (_, stderr, status) = launch(
            &home,
            repo.path(),
            &["config", "set", &format!("{guard}.mode"), "warn", "--force"],
        );
        assert!(
            status.success(),
            "setting {guard}.mode should succeed:\n{stderr}"
        );
    }

    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "a warn-mode launch must succeed:\n{stderr}");
    assert_eq!(
        stderr.matches("[WARN MODE]").count(),
        2,
        "both guards are in warn mode, so both summary rows must say so:\n{stderr}"
    );

    let show = config_show(&home, repo.path());
    for guard in ["gh_guard", "git_guard"] {
        // Bare `warn`, no source suffix: a value read from the global config
        // file prints unlabelled, because the header names that file. The
        // suffix marks the layers the header does not — `(default)`,
        // `(preset)`, `(local)`.
        assert_eq!(
            shown(&show, guard, "mode"),
            "warn",
            "`config show` must agree with the launch about {guard}.mode:\n{show}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}

// ════════════════════════════════════════════════════════════════════
// Path 2 — the local layer is visible everywhere it is in force
// ════════════════════════════════════════════════════════════════════

/// A port nothing is listening on, from the kernel rather than from a guess.
///
/// The proxy binds before the summary prints, so a launch in a test that hard
/// codes 8080 or 8443 fails with `Address already in use` on the developer
/// machines most likely to have something on them. Racy in principle — the
/// port is free when asked for and bound a moment later — and still strictly
/// better than the two most-occupied ports in the industry.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("the loopback should be bindable")
        .local_addr()
        .expect("a bound listener should have an address")
        .port()
}

/// The single `.toml` under the scratch HOME's `local/` directory.
fn local_file(home: &Path) -> PathBuf {
    std::fs::read_dir(home.join(".config/cplt/local"))
        .expect("a local config directory should exist")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .expect("a local config file should have been written")
}

/// An applied per-repo local file left no trace on any surface while its values
/// were in effect. `proxy.port` rather than `sandbox.repo_dirs`: repo_dirs got
/// its own summary row, and that one row was mistaken for the layer being
/// visible.
#[test]
fn golden_local_layer_is_named_by_launch_show_and_get() {
    require_launch!();
    let home = make_config_home("golden-local");
    let repo = temp_repo("navikt/spleis");

    let port = free_port().to_string();
    let (_, stderr, status) = launch(
        &home,
        repo.path(),
        &["config", "set", "--local", "proxy.port", &port],
    );
    assert!(status.success(), "set --local should succeed:\n{stderr}");
    let local = local_file(&home);
    let local_str = local.to_string_lossy().into_owned();

    // 1. The launch names the file it read.
    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "a launch with a local layer must succeed:\n{stderr}");
    assert!(
        stderr.contains(&format!("Local:    {local_str}")),
        "the launch must name the local config file on its own summary row — \
         the path appearing in some other line (a warning that it was ignored, \
         say) is the defect, not the fix:\n{stderr}"
    );
    // ...and the value is in force, not merely mentioned.
    assert!(
        stderr.contains(&format!("localhost:{port}")),
        "the local proxy.port must actually be the port the proxy binds:\n{stderr}"
    );

    // 2. `config show` names the file and labels the value.
    let show = config_show(&home, repo.path());
    assert!(
        show.contains(&local_str),
        "`config show` must name the local file:\n{show}"
    );
    assert_eq!(
        shown(&show, "proxy", "port"),
        format!("{port} (local)"),
        "`config show` must label the value as coming from the local layer:\n{show}"
    );

    // 3. `config get` says which layer answered.
    let (stdout, stderr, status) = launch(&home, repo.path(), &["config", "get", "proxy.port"]);
    assert!(status.success(), "config get should succeed:\n{stderr}");
    assert_eq!(stdout.trim(), port, "config get must return the value");
    assert!(
        stderr.contains("(local, this project only)"),
        "`config get` must say the answer came from the local layer:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ════════════════════════════════════════════════════════════════════
// Path 4 — the summary's claim about push matches what push does
// ════════════════════════════════════════════════════════════════════

/// Paths 1 and 2 assert that two of cplt's own surfaces agree with each other.
/// That is the shape of #410, but it is not enforcement: both could read a
/// correct `Resolved` while the PATH shim was never installed, and both tests
/// would pass. This one closes the loop — the summary line and the ref in the
/// remote have to tell the same story.
///
/// Both halves matter. The negative half exists elsewhere in the suite; the
/// positive half — that under the default policy a feature-branch push
/// actually *works* through a real launch — did not, and a guard that blocks
/// everything would have passed every test in the tree.
#[test]
fn golden_default_policy_pushes_a_feature_branch_and_refuses_the_default_one() {
    require_launch!();
    let home = make_config_home("golden-push");
    // Inside the checkout: the sandbox denies process-exec under /private/tmp,
    // so the git that runs in the sandbox cannot live there.
    let (_tmp, work, origin) = bare_origin_repo(Path::new(env!("CARGO_MANIFEST_DIR")));

    // What `protect_default_branch_only` protects is the *remote's* default
    // branch, which the guard reads from this ref — a repo built by `git init`
    // has none.
    let run = |args: &[&str]| {
        let out = common::git_cmd(&work)
            .args(args)
            .output()
            .expect("git should run");
        assert!(
            out.status.success(),
            "git {args:?} should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["push", "--quiet", "origin", "main"]);
    run(&[
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    ]);
    run(&["checkout", "--quiet", "-b", "feature/golden"]);
    run(&["commit", "--quiet", "--allow-empty", "-m", "work"]);

    // The bare origin is outside the project dir, so the sandbox would deny the
    // write on its own. Grant it: otherwise the refused half would be refused
    // by the sandbox rather than by the guard, and the allowed half could not
    // succeed at all — the test would pass for entirely the wrong reasons.
    let allow = origin.to_string_lossy().into_owned();
    let push = |branch: &str| {
        let mut args = vec![
            "--no-quiet",
            "--yes",
            "--no-validate",
            "--allow-write",
            &allow,
        ];
        args.extend_from_slice(&["exec", "--", "git", "push", "origin", branch]);
        launch(&home, &work, &args)
    };

    // The summary must say what it is about to do, precisely: the default
    // preset protects the default branch only, and a line reading "blocks git
    // push" while feature-branch pushes go through is the #410 shape again.
    let (_, stderr, status) = push("feature/golden");
    assert!(
        stderr.contains("git guard:     on"),
        "the guard must be on for this test to mean anything:\n{stderr}"
    );
    assert!(
        stderr.contains("blocks git push to the default branch"),
        "the summary must scope its claim to what the policy actually blocks:\n{stderr}"
    );
    assert!(
        status.success(),
        "a feature-branch push must succeed under the default policy:\n{stderr}"
    );
    assert!(
        common::git_ok(
            &origin,
            &["rev-parse", "--verify", "refs/heads/feature/golden"]
        ),
        "the feature branch must have reached the remote — a summary that says the push \
         was allowed and a remote with no ref is the same lie as #410, told the other \
         way round:\n{stderr}"
    );

    // And the half the summary claims to block.
    let (_, stderr, status) = push("main");
    assert!(
        !status.success(),
        "a push to the default branch must fail:\n{stderr}"
    );
    common::assert_refused(&stderr, status.success(), "default branch");
    // The refusal has to leave the operator somewhere. A block with no way
    // forward is how an agent session ends in a support request.
    assert!(
        stderr.contains("branch") && (stderr.contains("feature") || stderr.contains("allow_push")),
        "the refusal must name a way forward, not only the rule:\n{stderr}"
    );

    let head_before = common::git_cmd(&origin)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .expect("git should run");
    assert_eq!(
        String::from_utf8_lossy(&head_before.stdout).trim(),
        String::from_utf8_lossy(
            &common::git_cmd(&work)
                .args(["rev-parse", "origin/main"])
                .output()
                .expect("git should run")
                .stdout
        )
        .trim(),
        "the refused push must not have moved the remote's default branch"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ════════════════════════════════════════════════════════════════════
// Path 3 — every `config set` leaves a launchable config
// ════════════════════════════════════════════════════════════════════

/// Files and directories a representative value can point at.
#[derive(Clone)]
struct Scratch {
    dir: String,
    file: String,
}

/// Candidate values for one key: everything `cplt config set` might plausibly
/// be handed for it. The contract is per value, not per key — a `set` that
/// refuses is a pass.
/// Stand-in for "a git repository inside the launch repo", swapped for a real
/// path once the iteration has one.
const NESTED_REPO: &str = "<nested-repo>";

fn candidates(dotted: &str, ty: cplt::config::ConfigValueType, s: &Scratch) -> Vec<String> {
    use cplt::config::ConfigValueType as T;
    // Paths get two candidates. The bug this path generalises was a value that
    // `set` accepted and the launch then rejected forever — a path that does
    // not exist is the cheapest instance of that shape.
    let missing = "/nonexistent/cplt-golden-path";
    match dotted {
        "sandbox.preset" => vec!["standard".into()],
        "sandbox.agent" => vec!["shell".into()],
        "proxy.log_level" => vec!["error".into()],
        "gh_guard.mode" | "git_guard.mode" => vec!["block".into()],
        "gh_guard.unknown_command" => vec!["block".into()],
        "proxy.upstream" => vec!["http://127.0.0.1:9".into()],
        "proxy.allow_private_domains" | "proxy.upstream_no_proxy" => vec!["example.invalid".into()],
        "proxy.blocked_domains" | "proxy.allowed_domains" | "proxy.log_file" => {
            vec![s.file.clone(), missing.into()]
        }
        // Inside the launch repository, not beside it: `config set --local`
        // refuses a sibling today ("sibling repositories are not yet
        // supported"), so a scratch repo in the temp dir never reaches a
        // launch — and this is the key the bricking defect was found on.
        "sandbox.repo_dirs" => vec![NESTED_REPO.into(), missing.into()],
        "allow.read" | "allow.write" | "allow.exec" | "allow.socket" | "deny.paths" => {
            vec![s.dir.clone(), missing.into()]
        }
        "allow.localhost" => vec!["3000".into()],
        // An environment variable name, not the generic string: `deny.env`
        // validates the spelling, and the fallback candidate's hyphen is not
        // in `[A-Za-z0-9_]`.
        "deny.env" => vec!["CPLT_GOLDEN".into()],
        _ => match ty {
            // Both sides. `sandbox.scratch_dir = false` takes both guards to
            // `inactive` and `proxy.enabled = false` removes the proxy — the
            // "set accepts it, the launch never starts" shape is at least as
            // likely there as on the `true` side.
            T::Bool => vec!["true".into(), "false".into()],
            T::U16 | T::U16Array => vec![free_port().to_string()],
            T::U64 => vec!["30".into()],
            // A string key with no representative value of its own, and every
            // array of tables: `set` has no spelling for these, so the only
            // outcome under test is that it refuses rather than writing
            // something the launch cannot read.
            // `_` rather than the remaining variants by name: a value type
            // added to the registry must fall through to "set it and see", not
            // to a compile error in a test.
            _ => vec!["cplt-golden".into()],
        },
    }
}

/// A git repository inside `parent`, returned as a string path.
fn nested_repo(parent: &Path) -> String {
    let nested = parent.join("vendored-lib");
    std::fs::create_dir_all(&nested).expect("nested repo dir should be creatable");
    for args in [
        &["init", "-b", "main"][..],
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/navikt/vendored-lib.git",
        ][..],
    ] {
        let out = common::git_cmd(&nested)
            .args(args)
            .output()
            .expect("git should run");
        assert!(out.status.success(), "git {args:?} should succeed");
    }
    nested.to_string_lossy().into_owned()
}

/// Keys no launch in a test can exercise, with the reason. Kept explicit and
/// printed by the test, so a skip is a stated exception rather than a silent
/// hole.
const SKIPPED: &[(&str, &str)] = &[
    (
        "git_guard.allow_push",
        "an array of tables, which `config set` has no spelling for at all — it \
         is edited by hand. The refusal is asserted below instead of a launch.",
    ),
    (
        "allow.exec",
        "every directory a test can create is under the system temp dir or the \
     project dir, both of which the sandbox makes writable, and cplt refuses a \
     tree that is both writable and executable. A value that would launch \
     cannot be constructed here; `e2e.rs` covers the grant itself.",
    ),
];

/// Keys where a value `config set` accepts can still stop the launch, and that
/// is the deliberate behaviour: an allowlist file that is not there fails
/// closed rather than coming up allowing every domain, and a log file cplt
/// cannot open is not the audited run the operator asked for. Both refusals
/// name the value and the remedy, which is what this test then requires of
/// them. Both would be better still if `config set` warned about the missing
/// path the way the `allow.*` keys do; that gap is a finding, not a fix here.
const FAIL_CLOSED_AT_LAUNCH: &[&str] = &["proxy.allowed_domains", "proxy.log_file"];

/// The generic form of the `sandbox.repo_dirs /nonexistent` defect: a `config
/// set` that succeeds must leave a config the next launch can start from —
/// unless it warned about the value on the way in.
///
/// Three outcomes are a pass: `set` refuses the value; the launch succeeds; or
/// `set` warned about that exact value *and* the launch's refusal names it too,
/// which is the fail-closed path (a missing allowlist file) told to the
/// operator at both moments. The failure this catches is the fourth: a `set`
/// that says nothing and a launch that then never starts again.
///
/// Driven from the registry, so a key added tomorrow is covered without anyone
/// remembering to add it here.
#[test]
fn golden_every_config_set_leaves_a_launchable_config() {
    require_launch!();
    for (key, why) in SKIPPED {
        eprintln!("SKIPPED {key}: {why}");
    }
    let keys = cplt::config::all_config_keys();
    assert!(keys.len() > 20, "the registry should be non-trivial");

    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    let chunk = keys.len().div_ceil(threads);
    let (failures, launched): (Vec<String>, Vec<String>) = std::thread::scope(|scope| {
        let handles: Vec<_> = keys
            .chunks(chunk)
            .map(|chunk| scope.spawn(move || check_keys(chunk)))
            .collect();
        let mut failures = Vec::new();
        let mut launched = Vec::new();
        for handle in handles {
            let (f, l) = handle.join().expect("worker should not panic");
            failures.extend(f);
            launched.extend(l);
        }
        (failures, launched)
    });

    assert!(
        failures.is_empty(),
        "a `config set` that succeeded left a config no launch can start from:\n{}",
        failures.join("\n")
    );

    // The claim this test makes is "a key added tomorrow is covered". It is
    // only true if every key reached a launch: a key whose every candidate
    // `set` refuses is tested for nothing, and passes in silence. A new
    // validated string key gets `"cplt-golden"`, which `set` rejects — so
    // without this assertion the key would be added, the gate would stay green,
    // and no launch would ever have run with it.
    let uncovered: Vec<String> = keys
        .iter()
        .map(|info| format!("{}.{}", info.section, info.key))
        .filter(|dotted| !launched.contains(dotted) && !SKIPPED.iter().any(|(k, _)| k == dotted))
        .collect();
    assert!(
        uncovered.is_empty(),
        "no candidate value was accepted for these keys, so no launch ever ran with one \
         set. Give each a representative value in `candidates`, or add it to `SKIPPED` \
         with the reason:\n  {}",
        uncovered.join("\n  ")
    );

    // A skip naming a key that no longer exists is a hole that reads as a
    // decision.
    for (key, _) in SKIPPED {
        assert!(
            keys.iter()
                .any(|info| format!("{}.{}", info.section, info.key) == *key),
            "SKIPPED names `{key}`, which is not in the registry — renamed or removed?"
        );
    }
}

/// `(failures, keys that reached a launch)`.
fn check_keys(keys: &[cplt::config::ConfigKeyInfo]) -> (Vec<String>, Vec<String>) {
    let mut failures = Vec::new();
    let mut launched = Vec::new();
    for info in keys {
        let dotted = format!("{}.{}", info.section, info.key);
        if SKIPPED.iter().any(|(k, _)| *k == dotted) {
            continue;
        }
        for value in candidates(&dotted, info.value_type, &scratch()) {
            let home = make_config_home("golden-set");
            let repo = temp_repo("navikt/spleis");
            // Resolved here rather than in `candidates`: the value has to name
            // a repository inside *this* iteration's launch repo, which does
            // not exist until now.
            let value = if value == NESTED_REPO {
                nested_repo(repo.path())
            } else {
                value
            };
            let (_, mut set_err, mut set_status) = launch(
                &home,
                repo.path(),
                &["config", "set", &dotted, &value, "--force"],
            );
            // Some keys exist only in a narrower layer — `sandbox.repo_dirs`
            // in the per-repo local file, `deny.env` in the repo's own
            // `.cplt.toml` — and both refusals say which. Take the refusal's
            // own advice: a test that only ever set keys globally would skip
            // the very key the bricking defect was found on, and would call
            // "cannot be set here" coverage.
            for layer in ["--local", "--repo"] {
                if set_status.success() || !set_err.contains(layer) {
                    continue;
                }
                let (_, err, status) = launch(
                    &home,
                    repo.path(),
                    &["config", "set", layer, &dotted, &value, "--force"],
                );
                set_err = err;
                set_status = status;
            }
            if set_status.success() {
                launched.push(dotted.clone());
                let (_, stderr, ok) = launch_agent(&home, repo.path());
                // Excused: the operator was told about this value at the
                // moment it was set, or the refusal is the documented
                // fail-closed one. Either way the launch must still name it.
                let excused = (set_err.contains("Warning") && set_err.contains(&value))
                    || FAIL_CLOSED_AT_LAUNCH.contains(&dotted.as_str());
                let named = excused && stderr.contains(&value);
                if !ok && !named {
                    failures.push(format!(
                        "  {dotted} = {value}: `config set` accepted it{}, then the launch \
                         failed.\n{}",
                        if excused {
                            ", and the refusal does not name the value"
                        } else {
                            " without a warning"
                        },
                        indent(&stderr)
                    ));
                }
            } else {
                // The refusal must explain itself. A `set` that fails with no
                // reason is the same dead end as a launch that fails later.
                assert!(
                    !set_err.trim().is_empty(),
                    "{dotted} = {value}: `config set` refused with an empty message"
                );
            }
            let _ = std::fs::remove_dir_all(&home);
        }
    }
    (failures, launched)
}

/// Real paths for the keys that take one. Per worker thread, not per key: the
/// directory is only ever read.
fn scratch() -> Scratch {
    thread_local! {
        static SCRATCH: (tempfile::TempDir, Scratch) = build_scratch();
    }
    SCRATCH.with(|(_, s)| s.clone())
}

fn build_scratch() -> (tempfile::TempDir, Scratch) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir).expect("create dir");
    let file = tmp.path().join("list.txt");
    std::fs::write(&file, "example.invalid\n").expect("write file");
    let s = Scratch {
        dir: dir.to_string_lossy().into_owned(),
        file: file.to_string_lossy().into_owned(),
    };
    (tmp, s)
}

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ════════════════════════════════════════════════════════════════════
// The `.env` refusal names the bootstrap detection (#434 follow-up)
// ════════════════════════════════════════════════════════════════════

/// #434 taught `init` and `doctor` to say that a nais-shaped bootstrap meets
/// three refusals at once. At runtime the refusals still fired separately with
/// nothing connecting them, and the `.env` denial — the first one hit — said
/// only "secrets protected". It now names the script and the remedy.
#[test]
fn golden_env_denial_names_the_nais_bootstrap_it_detected() {
    require_launch!();
    let home = make_config_home("golden-nais");
    let repo = temp_repo("navikt/familie-ba-sak");
    std::fs::write(
        repo.path().join("hentEnv.sh"),
        "#!/usr/bin/env bash\n\
         if [[ \"$(nais device status)\" != *\"Connected\"* ]]; then exit 1; fi\n\
         nais app env myapp -e dev-gcp > .env\n",
    )
    .expect("write bootstrap script");
    std::fs::write(repo.path().join(".gitignore"), ".env\n").expect("write .gitignore");

    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "the launch must still succeed:\n{stderr}");
    assert!(
        stderr.contains(".env/.pem/.key blocked"),
        "test premise: the .env denial must be in force:\n{stderr}"
    );
    assert!(
        stderr.contains("hentEnv.sh"),
        "the .env denial must name the bootstrap script it detected:\n{stderr}"
    );
    assert!(
        stderr.contains("sandbox.allow_env_files"),
        "the .env denial must name the remedy:\n{stderr}"
    );

    // The other half: an ordinary repo gets none of it.
    let plain_home = make_config_home("golden-nais-plain");
    let plain = temp_repo("navikt/plain");
    let (_, plain_err, ok) = launch_agent(&plain_home, plain.path());
    assert!(ok, "the control launch must succeed:\n{plain_err}");
    assert!(
        !plain_err.contains("sandbox.allow_env_files"),
        "a repo with no bootstrap shape must not be told about one:\n{plain_err}"
    );

    let _ = std::fs::remove_dir_all(&home);
    let _ = std::fs::remove_dir_all(&plain_home);
}

// ════════════════════════════════════════════════════════════════════
// Path 5 — `check exec` answers the question the launch answers
// ════════════════════════════════════════════════════════════════════

/// `cplt check exec <cmd>` exists so a developer can ask what will happen
/// without launching an agent. It is therefore the one surface where telling
/// the truth about the guards *is* the feature.
///
/// It got warn mode wrong: `gate_git` and `gate` answer "does the policy
/// object", and `check exec` mapped every objection to BLOCKED — while the
/// launch consults the enforcement mode, prints a warning and runs the command.
/// A developer in warn mode was told a push would be blocked; the push went
/// through and the remote moved.
#[test]
fn golden_check_exec_agrees_with_the_launch_in_both_modes() {
    require_launch!();
    let home = make_config_home("golden-check");
    let (_tmp, work, origin) = bare_origin_repo(Path::new(env!("CARGO_MANIFEST_DIR")));

    let run = |args: &[&str]| {
        let out = common::git_cmd(&work)
            .args(args)
            .output()
            .expect("git should run");
        assert!(
            out.status.success(),
            "git {args:?} should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["push", "--quiet", "origin", "main"]);
    run(&[
        "symbolic-ref",
        "refs/remotes/origin/HEAD",
        "refs/remotes/origin/main",
    ]);
    run(&["commit", "--quiet", "--allow-empty", "-m", "work"]);

    let allow = origin.to_string_lossy().into_owned();
    let push = || {
        let args = vec![
            "--yes",
            "--no-validate",
            "--allow-write",
            &allow,
            "exec",
            "--",
            "git",
            "push",
            "origin",
            "main",
        ];
        launch(&home, &work, &args)
    };
    let head = || {
        String::from_utf8_lossy(
            &common::git_cmd(&origin)
                .args(["rev-parse", "refs/heads/main"])
                .output()
                .expect("git should run")
                .stdout,
        )
        .trim()
        .to_string()
    };

    // ── block mode: check says BLOCKED, and the push really is blocked ──
    let (check_out, check_err, status) = launch(
        &home,
        &work,
        &["check", "exec", "git", "push", "origin", "main"],
    );
    let check = format!("{check_out}{check_err}");
    assert!(status.success(), "check exec should run:\n{check}");
    assert!(
        check.contains("BLOCKED"),
        "in block mode `check exec` must say the push is blocked:\n{check}"
    );

    let before = head();
    let (_, stderr, push_status) = push();
    assert!(
        !push_status.success(),
        "the launch must agree with `check exec` and refuse:\n{stderr}"
    );
    assert_eq!(before, head(), "a blocked push must not move the remote");

    // ── warn mode: the launch runs the push, so check must not say BLOCKED ──
    let (_, stderr, status) = launch(
        &home,
        &work,
        &["config", "set", "git_guard.mode", "warn", "--force"],
    );
    assert!(
        status.success(),
        "setting warn mode should succeed:\n{stderr}"
    );

    let (check_out, check_err, status) = launch(
        &home,
        &work,
        &["check", "exec", "git", "push", "origin", "main"],
    );
    let check = format!("{check_out}{check_err}");
    assert!(
        status.success(),
        "check exec should run in warn mode:\n{check}"
    );
    assert!(
        check.contains("ALLOWED"),
        "warn mode lets the command run, so `check exec` must not report it \
         blocked — this is the drift the surface exists to prevent:\n{check}"
    );
    // Allowed, but not silently: the objection is still the operator's business.
    assert!(
        check.contains("warn mode"),
        "`check exec` must say why a command the guard objects to is allowed:\n{check}"
    );

    let before = head();
    let (_, stderr, push_status) = push();
    assert!(
        push_status.success(),
        "warn mode must let the push through, matching what `check exec` said:\n{stderr}"
    );
    assert_ne!(
        before,
        head(),
        "warn mode does not enforce, so the push must have reached the remote — \
         if it did not, `check exec` is now wrong in the other direction:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ════════════════════════════════════════════════════════════════════
// Path 6 — an untrusted `.cplt.toml` is announced, inert, then in force
// ════════════════════════════════════════════════════════════════════

/// The repo layer's whole security model is that `[propose]` does nothing until
/// a human approves it on this machine. Two failures are equally bad: a
/// proposal that applies before approval, and a summary that stays silent about
/// one waiting. Both are invisible to every test that only asserts on the
/// agent's view.
#[test]
fn golden_untrusted_repo_config_is_announced_inert_then_applied() {
    require_launch!();
    let home = make_config_home("golden-trust");
    let repo = temp_repo("navikt/spleis");

    // From git HEAD, not the working tree — so it has to be committed.
    std::fs::write(
        repo.path().join(".cplt.toml"),
        "[propose]\nallow_localhost_any = true\n",
    )
    .expect("write .cplt.toml");
    for args in [
        &["add", ".cplt.toml"][..],
        &["commit", "--quiet", "-m", "add cplt config"][..],
    ] {
        let out = common::git_cmd(repo.path())
            .args(args)
            .output()
            .expect("git should run");
        assert!(out.status.success(), "git {args:?} should succeed");
    }

    // 1. Announced, and not yet in force.
    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(
        ok,
        "an unapproved proposal must not stop the launch:\n{stderr}"
    );
    assert!(
        stderr.contains("Untrusted .cplt.toml"),
        "the summary must say a repo config is waiting for approval:\n{stderr}"
    );
    assert!(
        stderr.contains("cplt trust"),
        "and must name the command that shows it:\n{stderr}"
    );
    assert!(
        stderr.contains("Localhost:     blocked"),
        "an unapproved proposal must not be in force — this is the whole trust \
         model:\n{stderr}"
    );

    // 2. `cplt trust` shows it as pending rather than applied.
    let (stdout, stderr, status) = launch(&home, repo.path(), &["trust"]);
    let trust = format!("{stdout}{stderr}");
    assert!(status.success(), "cplt trust should succeed:\n{trust}");
    assert!(
        trust.contains("allow_localhost_any") && trust.contains("pending"),
        "`cplt trust` must list the proposal as pending:\n{trust}"
    );

    // 3. Approved, and now in force.
    let (stdout, stderr, status) = launch(&home, repo.path(), &["trust", "accept", "--all"]);
    assert!(
        status.success(),
        "trust accept should succeed:\n{stdout}{stderr}"
    );

    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "an approved launch must succeed:\n{stderr}");
    assert!(
        !stderr.contains("Untrusted .cplt.toml"),
        "an approved config must stop being announced as untrusted:\n{stderr}"
    );
    assert!(
        stderr.contains("Localhost:     all ports"),
        "after approval the proposal must actually apply:\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&home);
}

// ════════════════════════════════════════════════════════════════════
// Path 7 — the awkward repository states still launch, and say something true
// ════════════════════════════════════════════════════════════════════

/// A repository with no remote, a detached HEAD, or uncommitted changes is an
/// ordinary Tuesday, and none of the three was covered anywhere. The guards
/// read the remote's default branch, so "there isn't one" is a real input, and
/// the failure mode to avoid is a launch that dies on it or reports guards it
/// is not running.
#[test]
fn golden_awkward_repository_states_still_launch() {
    require_launch!();

    let commit = |dir: &Path, args: &[&str]| {
        let out = common::git_cmd(dir)
            .args(args)
            .output()
            .expect("git should run");
        assert!(
            out.status.success(),
            "git {args:?} should succeed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    // ── no remote at all ──
    let bare = tempfile::tempdir().expect("tempdir");
    commit(bare.path(), &["init", "--quiet", "-b", "main"]);
    commit(
        bare.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "init"],
    );

    let home = make_config_home("golden-noremote");
    let (_, stderr, ok) = launch_agent(&home, bare.path());
    assert!(
        ok,
        "a repository with no remote must still launch — the guards read the \
         remote's default branch, and not having one is not an error:\n{stderr}"
    );
    assert!(
        stderr.contains("git guard:     on"),
        "the guards still run with no remote, so the summary must still say so:\n{stderr}"
    );

    // ── detached HEAD ──
    let detached = temp_repo("navikt/spleis");
    commit(
        detached.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "one"],
    );
    commit(
        detached.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "two"],
    );
    commit(
        detached.path(),
        &["checkout", "--quiet", "--detach", "HEAD"],
    );

    let detached_home = make_config_home("golden-detached");
    let (_, stderr, ok) = launch_agent(&detached_home, detached.path());
    assert!(
        ok,
        "a detached HEAD must still launch — there is no current branch to \
         compare against the protected one:\n{stderr}"
    );
    assert!(
        stderr.contains("git guard:     on"),
        "the git guard must still be reported on a detached HEAD:\n{stderr}"
    );

    // ── uncommitted changes ──
    let dirty = temp_repo("navikt/spleis");
    commit(
        dirty.path(),
        &["commit", "--quiet", "--allow-empty", "-m", "init"],
    );
    std::fs::write(dirty.path().join("notes.txt"), "work in progress\n")
        .expect("write a dirty file");

    let dirty_home = make_config_home("golden-dirty");
    let (_, stderr, ok) = launch_agent(&dirty_home, dirty.path());
    assert!(
        ok,
        "uncommitted changes must not stop a launch — that is the state an \
         agent is usually asked to work in:\n{stderr}"
    );

    for h in [&home, &detached_home, &dirty_home] {
        let _ = std::fs::remove_dir_all(h);
    }
}

/// `cplt exec` always builds the Shell profile, whatever `--agent` says. That
/// is deliberate (#343) — but the flag was accepted and dropped in silence, so
/// `--agent copilot exec` answered questions about a different sandbox than the
/// operator believed they were probing. The profiles differ where it matters:
/// Shell has no Keychain grant, so `gh` finds no token.
///
/// The two sibling warnings beside this one (`--allow-docker`, `--allow-tmp-exec`)
/// have no test either; this is the shape of that gap, not just one message.
#[test]
fn golden_exec_says_when_it_ignores_the_requested_agent() {
    require_launch!();
    let home = make_config_home("golden-agent");
    let repo = temp_repo("navikt/spleis");

    let exec_with = |args: &[&str]| {
        let mut all = args.to_vec();
        all.extend_from_slice(&["--yes", "--no-validate", "exec", "--", TRUE_BIN]);
        launch(&home, repo.path(), &all)
    };

    let (_, stderr, status) = exec_with(&["--agent", "copilot"]);
    assert!(status.success(), "exec should still run:\n{stderr}");
    assert!(
        stderr.contains("--agent copilot is ignored"),
        "exec must say it is not building the profile that was asked for:\n{stderr}"
    );
    // A warning that only says "ignored" leaves the operator where they were.
    assert!(
        stderr.contains("check"),
        "and must name the command that does answer the question:\n{stderr}"
    );

    // Not suppressed by --quiet: the whole failure is the operator believing
    // something untrue about the sandbox they are looking at.
    let (_, stderr, _) = exec_with(&["--agent", "copilot", "--quiet"]);
    assert!(
        stderr.contains("--agent copilot is ignored"),
        "--quiet must not hide it:\n{stderr}"
    );

    // No flag, and the flag that matches what exec actually builds, stay quiet.
    for args in [&[][..], &["--agent", "shell"][..]] {
        let (_, stderr, _) = exec_with(args);
        assert!(
            !stderr.contains("is ignored"),
            "no warning is owed for {args:?}:\n{stderr}"
        );
    }

    let _ = std::fs::remove_dir_all(&home);
}
