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

// ════════════════════════════════════════════════════════════════════
// Path 2 — the local layer is visible everywhere it is in force
// ════════════════════════════════════════════════════════════════════

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

    let (_, stderr, status) = launch(
        &home,
        repo.path(),
        &["config", "set", "--local", "proxy.port", "8443"],
    );
    assert!(status.success(), "set --local should succeed:\n{stderr}");
    let local = local_file(&home);
    let local_str = local.to_string_lossy().into_owned();

    // 1. The launch names the file it read.
    let (_, stderr, ok) = launch_agent(&home, repo.path());
    assert!(ok, "a launch with a local layer must succeed:\n{stderr}");
    assert!(
        stderr.contains(&local_str),
        "the launch must name the local config file it applied:\n{stderr}"
    );
    // ...and the value is in force, not merely mentioned.
    assert!(
        stderr.contains("localhost:8443"),
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
        "8443 (local)",
        "`config show` must label the value as coming from the local layer:\n{show}"
    );

    // 3. `config get` says which layer answered.
    let (stdout, stderr, status) = launch(&home, repo.path(), &["config", "get", "proxy.port"]);
    assert!(status.success(), "config get should succeed:\n{stderr}");
    assert_eq!(stdout.trim(), "8443", "config get must return the value");
    assert!(
        stderr.contains("local"),
        "`config get` must say the answer came from the local layer:\n{stderr}"
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
    repo: String,
}

/// Candidate values for one key: everything `cplt config set` might plausibly
/// be handed for it. The contract is per value, not per key — a `set` that
/// refuses is a pass.
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
        "sandbox.repo_dirs" => vec![s.repo.clone(), missing.into()],
        "allow.read" | "allow.write" | "allow.exec" | "allow.socket" | "deny.paths" => {
            vec![s.dir.clone(), missing.into()]
        }
        "allow.localhost" => vec!["3000".into()],
        _ => match ty {
            T::Bool => vec!["true".into()],
            T::U16 | T::U16Array => vec!["8080".into()],
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

/// Keys no launch in a test can exercise, with the reason. Kept explicit and
/// printed by the test, so a skip is a stated exception rather than a silent
/// hole.
const SKIPPED: &[(&str, &str)] = &[(
    "allow.exec",
    "every directory a test can create is under the system temp dir or the \
     project dir, both of which the sandbox makes writable, and cplt refuses a \
     tree that is both writable and executable. A value that would launch \
     cannot be constructed here; `e2e.rs` covers the grant itself.",
)];

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
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = keys
            .chunks(chunk)
            .map(|chunk| scope.spawn(move || check_keys(chunk)))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("worker should not panic"))
            .collect()
    });

    assert!(
        failures.is_empty(),
        "a `config set` that succeeded left a config no launch can start from:\n{}",
        failures.join("\n")
    );
}

fn check_keys(keys: &[cplt::config::ConfigKeyInfo]) -> Vec<String> {
    let mut failures = Vec::new();
    for info in keys {
        let dotted = format!("{}.{}", info.section, info.key);
        if SKIPPED.iter().any(|(k, _)| *k == dotted) {
            continue;
        }
        for value in candidates(&dotted, info.value_type, &scratch()) {
            let home = make_config_home("golden-set");
            let repo = temp_repo("navikt/spleis");
            let (_, mut set_err, mut set_status) = launch(
                &home,
                repo.path(),
                &["config", "set", &dotted, &value, "--force"],
            );
            // Some keys exist only in the per-repo layer — `sandbox.repo_dirs`
            // is one, and it is the key the bricking defect was found on, so a
            // test that only ever set keys globally would skip the very case it
            // generalises. Take the refusal's own advice and set it there.
            if !set_status.success() && set_err.contains("--local") {
                let (_, err, status) = launch(
                    &home,
                    repo.path(),
                    &["config", "set", "--local", &dotted, &value, "--force"],
                );
                set_err = err;
                set_status = status;
            }
            if set_status.success() {
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
    failures
}

/// Real paths for the keys that take one. Per worker thread, not per key: the
/// directory is only ever read.
fn scratch() -> Scratch {
    thread_local! {
        static SCRATCH: (tempfile::TempDir, tempfile::TempDir, Scratch) = build_scratch();
    }
    SCRATCH.with(|(_, _, s)| s.clone())
}

fn build_scratch() -> (tempfile::TempDir, tempfile::TempDir, Scratch) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("dir");
    std::fs::create_dir_all(&dir).expect("create dir");
    let file = tmp.path().join("list.txt");
    std::fs::write(&file, "example.invalid\n").expect("write file");
    // `sandbox.repo_dirs` names repositories, not directories.
    let (repo_tmp, work, _origin) = bare_origin_repo(tmp.path());
    let s = Scratch {
        dir: dir.to_string_lossy().into_owned(),
        file: file.to_string_lossy().into_owned(),
        repo: work.to_string_lossy().into_owned(),
    };
    (tmp, repo_tmp, s)
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
