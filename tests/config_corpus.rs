//! The golden corpus for config resolution (#427, step 0).
//!
//! This file is a **security artefact**, and is meant to be reviewed as one.
//!
//! #427 proposes replacing the hand-rolled precedence code with a table. That
//! refactor touches the code four advisories were fixed in this week — #381
//! (an explicit deny re-opened by an overlapping grant), #382 (push
//! authorization not bound to the destination), #420 (push rules trusting
//! agent-writable state), #410 (guard defaults reported wrongly). A silent
//! regression there does not look like a broken test; it looks like a sandbox
//! that still starts.
//!
//! So before anything moves, this records what resolution does **today**, as
//! data: inputs in, values out, expectations written by hand rather than
//! computed. Two properties make it useful:
//!
//! 1. **It is readable without running it.** Each case names what it pins and
//!    why. A reviewer can disagree with an expectation on sight, which is not
//!    true of a test that asserts `resolved == resolve(input)`.
//! 2. **It does not depend on the machine's configuration.** No `HOME`, no
//!    process environment — `merge_local_with_no_proxy_env` takes the ambient
//!    `NO_PROXY` as an argument for exactly this reason — so cases are
//!    order-independent and the refactor can dual-run them against both
//!    implementations.
//!
//! It does read the **filesystem**, and that is not an oversight in the test:
//! writing this corpus is how I found out. Three behaviours emerged from cases
//! that failed on their first run, each of which the refactor has to preserve —
//! and each of which is **narrower than it first looks**. An earlier draft of
//! this comment stated all three as general rules, which would have told
//! whoever implements the table to build the wrong thing.
//!
//! - In the **global and local files**, an `allow.read` entry that does not
//!   exist is **dropped** with a warning, while a `deny.paths` entry that
//!   cannot be resolved is a **hard error** that stops the launch: "Silently
//!   dropping deny rules is a security risk." That asymmetry is the
//!   tighten-only rule doing its job and is the most important thing here.
//! - It does **not** hold for the repo layer. `apply_repo_config` resolves
//!   `[deny]` paths with `canonicalize_deepest`, which keeps a not-yet-created
//!   tail, so a repo may deny a path that does not exist yet — deliberately,
//!   since the repo is describing the project rather than this checkout. A
//!   table implementing "unresolvable tighten-only entries are a hard error"
//!   uniformly would break that.
//! - CLI paths are appended by the resolver and canonicalized elsewhere
//!   (`main.rs`), outside the code #427 replaces. So "paths are canonicalized"
//!   is true of what reaches the sandbox, not of this function.
//!
//! `HOME` is read during resolution — `config_dir()` anchors relative paths and
//! the subscription cache — so the accurate claim is narrower than "no HOME":
//! every case here uses absolute paths, so `HOME` cannot change the outcome.
//!
//! The cases below therefore use paths that exist on any machine (`/usr`,
//! `/etc`). A corpus that quietly asserted on dropped grants would have
//! recorded nothing.
//!
//! It is worth something even if #427 is never built: several of these
//! behaviours were only ever asserted through a full launch, and three had no
//! test at all.

#![allow(clippy::disallowed_methods)]

use cplt::config::{CliFlags, Config, EnforcementMode, Preset, Resolved};

/// One corpus case: inputs, and what they must resolve to.
struct Case {
    /// What this pins, in the imperative. Printed on failure.
    name: &'static str,
    /// Why it is here — an advisory, an issue, or the rule it protects.
    /// A case with no reason to exist is a case nobody will dare delete.
    why: &'static str,
    /// `~/.config/cplt/config.toml`.
    global: &'static str,
    /// The per-repo user layer, `~/.config/cplt/local/<hash>.toml`.
    local: Option<&'static str>,
    /// `.cplt.toml` from git HEAD, plus the `[propose]` keys the human has
    /// accepted on this machine. #427 defines a case as
    /// `(global, repo + accepted keys, CLI)`, and `apply_repo_config` is the
    /// second resolver the refactor deletes — so a corpus without it cannot
    /// see the behaviour most likely to change.
    repo: Option<(&'static str, &'static [&'static str])>,
    /// CLI flags for this run.
    cli: fn() -> CliFlags,
    /// The ambient `NO_PROXY`, passed in rather than read.
    no_proxy_env: Option<&'static str>,
    /// What must be true of the result. Panics with its own message.
    ///
    /// `None` means resolution is expected to *fail*; see `expect_err`. An
    /// equality harness has to agree on which inputs are refused, not only on
    /// what the accepted ones produce.
    expect: Option<fn(&Resolved)>,
    /// A substring the refusal must contain, when resolution must fail.
    expect_err: Option<&'static str>,
}

/// Resolve one case the way a launch does, minus the world.
///
/// # Panics
/// If the case expects success and resolution fails, or vice versa.
fn resolve(case: &Case) -> Option<Resolved> {
    let global = Config::parse(case.global)
        .unwrap_or_else(|e| panic!("{}: global config should parse: {e}", case.name));
    let local = case.local.map(|text| {
        Config::parse(text)
            .unwrap_or_else(|e| panic!("{}: local config should parse: {e}", case.name))
    });
    let outcome = global.merge_local_with_no_proxy_env(
        local.as_ref(),
        (case.cli)(),
        case.no_proxy_env.map(str::to_string),
    );
    let mut resolved = match (outcome, case.expect_err) {
        (Ok(r), None) => r,
        (Ok(_), Some(needle)) => panic!(
            "{}: resolution should have been refused with {needle:?}, but it succeeded",
            case.name
        ),
        (Err(e), Some(needle)) => {
            let message = e.to_string();
            assert!(
                message.contains(needle),
                "{}: the refusal must name {needle:?}, got: {message}",
                case.name
            );
            return None;
        }
        (Err(e), None) => panic!("{}: resolution should succeed: {e}", case.name),
    };
    if let Some((text, accepted)) = case.repo {
        let repo_config = cplt::repo_config::parse_and_validate(text)
            .unwrap_or_else(|e| panic!("{}: .cplt.toml should parse: {e}", case.name));
        // The directory the `.cplt.toml` was read from — repo paths anchor to
        // it, and `resolve_repo_allow_path` refuses one that escapes it.
        let dir = std::path::Path::new("/usr");
        resolved.apply_repo_config(&repo_config, dir, accepted);
    }
    Some(resolved)
}

fn no_flags() -> CliFlags {
    CliFlags::default()
}

// ════════════════════════════════════════════════════════════════════
// The corpus
// ════════════════════════════════════════════════════════════════════

const CORPUS: &[Case] = &[
    // ── Defaults ────────────────────────────────────────────────────
    Case {
        name: "an empty config resolves both guards on, in block mode",
        why: "#410 reported both guards disabled while they were enforcing, and \
              #335 changed the mode default. The pair is the single most \
              load-bearing default in the product.",
        global: "",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(r.gh_guard.enabled, "gh guard must default on");
            assert!(r.git_guard.enabled, "git guard must default on");
            assert_eq!(
                r.gh_guard.mode,
                EnforcementMode::Block,
                "gh guard must default to block, not warn"
            );
            assert_eq!(
                r.git_guard.mode,
                EnforcementMode::Block,
                "git guard must default to block, not warn"
            );
        }),
    },
    Case {
        name: "the default policy protects the default branch only",
        why: "#387. It is what makes a feature-branch push work at all, so \
              flipping it silently would look like the guard tightening rather \
              than like a bug.",
        global: "",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.git_guard.protect_default_branch_only,
                "the standard preset protects the default branch only"
            );
        }),
    },
    Case {
        name: "an empty config leaves the dangerous toggles off",
        why: "Every one of these is a documented escape hatch. A default that \
              drifts to `true` is a sandbox that stops sandboxing, and nothing \
              in a launch would look different.",
        global: "",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(!r.allow_docker, "allow_docker must default off");
            assert!(!r.allow_tmp_exec, "allow_tmp_exec must default off");
            assert!(
                !r.allow_lifecycle_scripts,
                "allow_lifecycle_scripts must default off"
            );
            assert!(!r.allow_env_files, "allow_env_files must default off");
            assert!(
                !r.allow_localhost_any,
                "allow_localhost_any must default off"
            );
        }),
    },
    // ── Presets ─────────────────────────────────────────────────────
    Case {
        name: "the permissive preset turns the guards off",
        why: "The inverse of #410: an operator who reads `on` and is not \
              protected is no worse off than one who reads `off` and is.",
        global: "[sandbox]\npreset = \"permissive\"\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(!r.gh_guard.enabled, "permissive turns the gh guard off");
            assert!(!r.git_guard.enabled, "permissive turns the git guard off");
        }),
    },
    Case {
        name: "the strict preset blocks every push, not only the default branch",
        why: "The one preset difference that changes what a developer can do \
              day to day.",
        global: "[sandbox]\npreset = \"strict\"\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(r.git_guard.enabled, "strict keeps the git guard on");
            assert!(
                !r.git_guard.protect_default_branch_only,
                "strict protects every branch, not just the default one"
            );
        }),
    },
    Case {
        name: "an explicit config value beats the preset baseline",
        why: "The preset is a baseline, not a ceiling. If this inverts, every \
              `--no-…` opt-out silently stops working.",
        global: "[sandbox]\npreset = \"permissive\"\n\n[gh_guard]\nenabled = true\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.gh_guard.enabled,
                "an explicit gh_guard.enabled must beat the preset that turns it off"
            );
        }),
    },
    // ── The CLI layer ───────────────────────────────────────────────
    Case {
        name: "a CLI preset beats a config preset",
        why: "`--preset` is the flag someone reaches for when the config is \
              wrong for one run.",
        global: "[sandbox]\npreset = \"strict\"\n",
        local: None,
        repo: None,
        cli: || CliFlags {
            preset: Some(Preset::Permissive),
            ..CliFlags::default()
        },
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                !r.gh_guard.enabled,
                "--preset permissive must beat `preset = strict` in the file"
            );
        }),
    },
    // ── The local layer (#340/#429) ─────────────────────────────────
    Case {
        name: "a local scalar beats the global one",
        why: "#340's core promise. If it inverts, a per-project setting reads \
              as applied and is not.",
        global: "[proxy]\nport = 8080\n",
        local: Some("[proxy]\nport = 9090\n"),
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert_eq!(r.proxy_port, 9090, "local proxy.port must win");
        }),
    },
    Case {
        name: "a local boolean beats the global one",
        why: "Booleans resolve through a different path than scalars — the \
              #310 ladder — so they need their own case.",
        global: "[sandbox]\nallow_docker = false\n",
        local: Some("[sandbox]\nallow_docker = true\n"),
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(r.allow_docker, "local allow_docker = true must win");
            // The value alone does not prove the ladder saw the local layer:
            // `overlay` copies the boolean into the global struct before the
            // ladder runs, so a resolver ignoring `local` entirely would still
            // produce `true`. The layer is the part under test.
            assert_eq!(
                r.bool_layer("sandbox", "allow_docker"),
                Some(cplt::config::ConfigLayer::Local),
                "and must be attributed to the local layer, not the global one"
            );
        }),
    },
    Case {
        name: "lists union across global and local rather than replacing",
        why: "A local `allow.read` that silently dropped the global entries \
              would take away access the operator never revoked.",
        global: "[allow]\nread = [\"/usr\"]\n",
        local: Some("[allow]\nread = [\"/etc\"]\n"),
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            let read: Vec<String> = r
                .allow_read
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            assert!(
                read.iter().any(|p| p == "/usr"),
                "the global entry must survive a local list: {read:?}"
            );
            // `/etc` is a symlink to `/private/etc` on macOS, and resolution
            // canonicalizes — itself a recorded behaviour. Compared against the
            // real canonical form rather than a suffix, so a resolver that
            // emitted some other path ending in "etc" would not pass.
            let etc = std::fs::canonicalize("/etc").expect("/etc should exist");
            assert!(
                read.iter().any(|p| std::path::Path::new(p) == etc),
                "the local entry must be present as {}: {read:?}",
                etc.display()
            );
        }),
    },
    Case {
        name: "a key set only globally still applies when a local file exists",
        why: "The overlay is a merge, not a replacement. If a local file \
              shadowed the whole global config, setting one local key would \
              silently drop every global grant.",
        global: "[sandbox]\nallow_docker = true\n\n[proxy]\nport = 8080\n",
        local: Some("[proxy]\nport = 9090\n"),
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.allow_docker,
                "a global value must survive a local file that does not mention it"
            );
            assert_eq!(r.proxy_port, 9090);
        }),
    },
    // ── Deny, and the advisory cases ────────────────────────────────
    Case {
        name: "deny.paths survives a config that also grants read",
        why: "GHSA/#381: an explicit deny was silently re-opened by an \
              overlapping grant. The profile builder is what fixes that, but a \
              deny that never reaches the resolver cannot be enforced by \
              anything downstream.",
        global: "[allow]\nread = [\"/usr\"]\n\n[deny]\npaths = [\"/usr/share\"]\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            let denied: Vec<String> = r
                .deny_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            assert!(
                denied.iter().any(|p| p == "/usr/share"),
                "the explicit deny must reach the resolved config: {denied:?}"
            );
        }),
    },
    Case {
        name: "a local deny adds to the global one instead of replacing it",
        why: "Tighten-only keys must never lose an element to a higher layer. \
              A local file that removed a global deny would be a widening \
              disguised as a list assignment.",
        global: "[deny]\npaths = [\"/usr/share\"]\n",
        local: Some("[deny]\npaths = [\"/usr/lib\"]\n"),
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            let denied: Vec<String> = r
                .deny_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            assert!(
                denied.iter().any(|p| p == "/usr/share"),
                "a global deny must survive a local deny list: {denied:?}"
            );
            assert!(
                denied.iter().any(|p| p == "/usr/lib"),
                "the local deny must be present: {denied:?}"
            );
        }),
    },
    // ── Guard detail that advisories turned on ──────────────────────
    Case {
        name: "guard mode resolves independently of guard enablement",
        why: "#410's shape: two fields on one surface, read from different \
              places. `enabled = true, mode = warn` is a guard that runs and \
              stops nothing, and it must be expressible without ambiguity.",
        global: "[git_guard]\nenabled = true\nmode = \"warn\"\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(r.git_guard.enabled, "the guard is enabled");
            assert_eq!(
                r.git_guard.mode,
                EnforcementMode::Warn,
                "and runs in warn mode — enabled and mode are separate facts"
            );
        }),
    },
    Case {
        name: "an empty allow_push rule list is not a rule that allows everything",
        why: "H-10/#382: push authorization must be bound to a destination. An \
              empty rule set is 'no exceptions', never 'any push'.",
        global: "[git_guard]\nenabled = true\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.git_guard.allow_push.is_empty(),
                "no rules configured means no exceptions"
            );
            assert!(
                r.git_guard.enabled,
                "and the guard is still on — an empty exception list is not a disabled guard"
            );
        }),
    },
    // ── proxy.upstream_no_proxy, the one list with an exception ─────
    Case {
        name: "the ambient NO_PROXY reaches upstream_no_proxy",
        why: "The only key that reads the environment. #427 keeps it as a named \
              exception rather than folding it into the general rule, so the \
              exception needs a case that fails if it is quietly removed.",
        global: "",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: Some("internal.example.no"),
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.proxy_upstream_no_proxy
                    .iter()
                    .any(|d| d.contains("internal.example.no")),
                "the ambient NO_PROXY must reach the resolved config: {:?}",
                r.proxy_upstream_no_proxy
            );
        }),
    },
    Case {
        name: "no ambient NO_PROXY leaves the configured list alone",
        why: "The other half: an absent environment variable must not clear \
              what the file configured.",
        global: "[proxy]\nupstream_no_proxy = [\"configured.example.no\"]\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.proxy_upstream_no_proxy
                    .iter()
                    .any(|d| d.contains("configured.example.no")),
                "the configured list must survive an absent NO_PROXY: {:?}",
                r.proxy_upstream_no_proxy
            );
        }),
    },
    // ── The behaviours this file's header records ───────────────────
    Case {
        name: "a global allow.read path that does not exist is dropped",
        why: "The permissive half of the allow/deny asymmetry. A grant for a \
              path that is not there never reaches the sandbox, and the launch \
              continues — the opposite of what the same input does under deny.",
        global: "[allow]\nread = [\"/opt/definitely-not-here-cplt\"]\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                !r.allow_read
                    .iter()
                    .any(|p| p.to_string_lossy().contains("definitely-not-here")),
                "a nonexistent allow.read entry must not reach the sandbox: {:?}",
                r.allow_read
            );
        }),
    },
    Case {
        name: "a global deny.paths entry that does not exist refuses the launch",
        why: "The strict half, and the most important line in this file. A deny \
              rule that cannot be resolved is not silently dropped, because a \
              dropped deny is a grant nobody asked for.",
        global: "[deny]\npaths = [\"/opt/definitely-not-here-cplt\"]\n",
        local: None,
        repo: None,
        cli: no_flags,
        no_proxy_env: None,
        expect_err: Some("cannot be resolved"),
        expect: None,
    },
    // ── The repo layer (`.cplt.toml`) ───────────────────────────────
    Case {
        name: "a repo deny.paths entry that does not exist is kept, not refused",
        why: "The exception to the rule above, and the one a uniform \
              tighten-only rule would break. Repo config resolves deny paths \
              with `canonicalize_deepest`, keeping a not-yet-created tail, \
              because the repo describes the project rather than this checkout.",
        global: "",
        local: None,
        repo: Some(("[deny]\npaths = [\"build/secrets\"]\n", &[])),
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.deny_paths
                    .iter()
                    .any(|p| p.to_string_lossy().contains("build/secrets")),
                "a repo deny for a path that does not exist yet must survive: {:?}",
                r.deny_paths
            );
        }),
    },
    Case {
        name: "an unapproved repo proposal does not apply",
        why: "The repo layer's entire trust model. `.cplt.toml` is written by a \
              tree the agent can edit, so a proposal must do nothing until a \
              human accepts it on this machine.",
        global: "",
        local: None,
        repo: Some(("[propose]\nallow_docker = true\n", &[])),
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                !r.allow_docker,
                "an unaccepted [propose] key must not take effect"
            );
        }),
    },
    Case {
        name: "an accepted repo proposal applies",
        why: "The other half — acceptance has to actually do something, or the \
              trust flow is theatre.",
        global: "",
        local: None,
        repo: Some(("[propose]\nallow_docker = true\n", &["allow_docker"])),
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(r.allow_docker, "an accepted [propose] key must take effect");
        }),
    },
    Case {
        name: "repo deny applies with no acceptance at all",
        why: "`[deny]` needs no approval because nothing it can express widens. \
              If this ever required acceptance, every repo that tightens would \
              silently stop tightening.",
        global: "",
        local: None,
        repo: Some(("[deny]\nenv = [\"VAULT_TOKEN\"]\n", &[])),
        cli: no_flags,
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.deny_env.iter().any(|v| v == "VAULT_TOKEN"),
                "a repo [deny] entry applies unaccepted: {:?}",
                r.deny_env
            );
        }),
    },
    // ── proxy.upstream_no_proxy: the CLI-replaces exception ─────────
    Case {
        name: "the CLI replaces upstream_no_proxy rather than unioning it",
        why: "The one list key where the CLI does not union, kept deliberately \
              (#427 open question 2): someone passing an explicit no-proxy list \
              means that list, and silently adding to a proxy bypass list is \
              the wrong direction to be wrong in. Pinned so the table cannot \
              fold it into the general rule by accident.",
        global: "[proxy]\nupstream_no_proxy = [\"from-config.example.no\"]\n",
        local: None,
        repo: None,
        cli: || CliFlags {
            proxy_upstream_no_proxy: vec!["from-cli.example.no".to_string()],
            ..CliFlags::default()
        },
        no_proxy_env: None,
        expect_err: None,
        expect: Some(|r| {
            assert!(
                r.proxy_upstream_no_proxy
                    .iter()
                    .any(|d| d.contains("from-cli")),
                "the CLI value must be in force: {:?}",
                r.proxy_upstream_no_proxy
            );
            assert!(
                !r.proxy_upstream_no_proxy
                    .iter()
                    .any(|d| d.contains("from-config")),
                "and it replaces the configured list rather than unioning with \
                 it: {:?}",
                r.proxy_upstream_no_proxy
            );
        }),
    },
];

#[test]
fn corpus_resolves_as_recorded() {
    let mut failures = Vec::new();
    for case in CORPUS {
        // Inside the catch, so one case that panics on an unexpected refusal
        // reports itself instead of aborting the whole corpus.
        if let Err(panic) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let (Some(resolved), Some(expect)) = (resolve(case), case.expect) {
                expect(&resolved);
            }
        })) {
            let message = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_else(|| "unknown panic".to_string());
            failures.push(format!(
                "  {}\n    why: {}\n    {}",
                case.name, case.why, message
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "config resolution changed against the recorded corpus.\n\n\
         Each entry below records a behaviour someone decided on purpose, and \
         several were written after an advisory. If a change here is intended, \
         change the case in the same commit and say why in the message — do not \
         adjust it to match new output.\n\n{}",
        failures.join("\n\n")
    );
}

/// The corpus is only worth what its cases say. A case with no `why` is one
/// nobody will dare change and nobody can review.
#[test]
fn every_case_explains_itself() {
    for case in CORPUS {
        assert!(
            case.why.len() > 40,
            "{}: `why` must say what this protects, not restate the name",
            case.name
        );
        assert!(
            !case.name.is_empty(),
            "every case needs a name; it is what a failure prints"
        );
    }
}

/// Resolution must be deterministic: same inputs, same machine, same answer.
///
/// Not "pure" — resolution stats and canonicalizes paths, as the module
/// comment records. What this rules out is a resolver that depends on call
/// order or on mutable global state, which is what would make the corpus
/// unreliable as evidence during a dual-run.
#[test]
fn resolution_is_deterministic() {
    for case in CORPUS {
        let (Some(first), Some(second)) = (resolve(case), resolve(case)) else {
            continue;
        };
        // The whole struct, not three fields: `Resolved` derives `Debug`, and
        // the debug form includes `bool_layers`, so this compares provenance
        // too. It is also what a dual-run harness would compare, so a case
        // that passes here is one that can be compared there.
        assert_eq!(
            format!("{first:?}"),
            format!("{second:?}"),
            "{}: resolving twice gave a different result",
            case.name
        );
    }
}

/// A corpus that does not grow with the config surface stops being a corpus.
/// Not a count of keys — an assertion that the corpus covers each *kind* of
/// resolution the refactor will have to reproduce.
#[test]
fn the_corpus_covers_every_merge_kind() {
    let names: Vec<&str> = CORPUS.iter().map(|c| c.name).collect();
    for (kind, needle) in [
        ("a scalar (Replace)", "local scalar beats"),
        ("a boolean ladder value", "local boolean beats"),
        ("a union list", "union across global and local"),
        ("a tighten-only list", "local deny adds to the global"),
        ("the preset baseline", "preset baseline"),
        ("the CLI layer", "CLI preset beats"),
        ("the environment", "ambient NO_PROXY"),
        ("the repo layer, unaccepted", "unapproved repo proposal"),
        ("the repo layer, accepted", "accepted repo proposal"),
        ("repo deny, which needs no acceptance", "repo deny applies"),
        ("a refusal outcome", "refuses the launch"),
        ("the CLI-replaces exception", "replaces upstream_no_proxy"),
    ] {
        assert!(
            names.iter().any(|n| n.contains(needle)),
            "the corpus has no case for {kind} — #427 has to reproduce that \
             behaviour, so it needs one before the refactor starts"
        );
    }
}
