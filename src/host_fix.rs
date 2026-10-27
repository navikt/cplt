//! Interactive host fixes (#838): `cplt doctor --fix` and the MCP broker's
//! refusal at launch offer to run a fix on the host, after showing exactly
//! what runs.
//!
//! The fixes are a fixed table in this file. Nothing from config, specs or
//! the environment ever becomes a command. Root comes only through `sudo`'s
//! own prompt, and the offer is never made with `--yes`, without a terminal,
//! under CI, or inside a cplt sandbox (where it would be the agent asking).

use std::io::{IsTerminal, Write};
use std::process::{Command, Stdio};

use crate::doctor::{APPARMOR_BWRAP_PROFILE, Bubblewrap, SHIPPED_BWRAP_PROFILE};

/// A host problem with a known fix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// No bwrap in a trusted directory.
    BwrapMissing,
    /// `kernel.apparmor_restrict_unprivileged_userns = 1` and bwrap's probe fails.
    AppArmorUserns,
    /// No xdg-dbus-proxy in a trusted directory: a brokered MCP server with
    /// a keychain login gets no session bus (#849).
    DbusProxyMissing,
}

impl Problem {
    /// The tool the fix makes work.
    fn tool(self) -> &'static str {
        match self {
            Problem::DbusProxyMissing => "xdg-dbus-proxy",
            _ => "bubblewrap",
        }
    }
}

/// One command. `stdin` is fed to it; a `tee` step's stdout is discarded.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub argv: &'static [&'static str],
    pub stdin: Option<&'static str>,
}

const PROFILE_PATH: &str = "/etc/apparmor.d/bwrap";

const APPARMOR: &[Step] = &[
    Step {
        argv: &["sudo", "tee", PROFILE_PATH],
        stdin: Some(APPARMOR_BWRAP_PROFILE),
    },
    Step {
        argv: &["sudo", "apparmor_parser", "-r", PROFILE_PATH],
        stdin: None,
    },
];
const APPARMOR_SHIPPED: &[Step] = &[Step {
    argv: &["sudo", "apparmor_parser", "-r", SHIPPED_BWRAP_PROFILE],
    stdin: None,
}];
const APT: &[Step] = &[Step {
    argv: &["sudo", "apt-get", "install", "-y", "bubblewrap"],
    stdin: None,
}];
const DNF: &[Step] = &[Step {
    argv: &["sudo", "dnf", "install", "-y", "bubblewrap"],
    stdin: None,
}];
const APT_DBUS_PROXY: &[Step] = &[Step {
    argv: &["sudo", "apt-get", "install", "-y", "xdg-dbus-proxy"],
    stdin: None,
}];
const DNF_DBUS_PROXY: &[Step] = &[Step {
    argv: &["sudo", "dnf", "install", "-y", "xdg-dbus-proxy"],
    stdin: None,
}];

/// The fixable problem behind a bubblewrap state, if any.
#[must_use]
pub fn problem(state: &Bubblewrap, apparmor: bool) -> Option<Problem> {
    match state {
        Bubblewrap::NotInstalled => Some(Problem::BwrapMissing),
        Bubblewrap::Unusable { .. } if apparmor => Some(Problem::AppArmorUserns),
        _ => None,
    }
}

/// The problem that keeps the MCP broker from starting at launch, if it has
/// a fix here: bwrap missing, or AppArmor blocking its user namespaces.
/// Nothing when bubblewrap is turned off or a flag rules the broker out,
/// since no host fix changes that.
#[must_use]
pub fn launch_problem(config: &crate::sandbox::SandboxConfig) -> Option<Problem> {
    #[cfg(target_os = "linux")]
    {
        if config.use_bubblewrap == Some(false)
            || crate::sandbox::mcp_flag_conflict(
                config.allow_gpg_signing,
                config.allow_rootless_docker,
            )
            .is_some()
        {
            return None;
        }
        if crate::sandbox::bubblewrap_probe::check_availability().is_none() {
            return Some(Problem::BwrapMissing);
        }
        if crate::doctor::apparmor_restricts_userns()
            && crate::sandbox::mcp_wrapper_error(config).is_some()
        {
            return Some(Problem::AppArmorUserns);
        }
    }
    let _ = config;
    None
}

/// The steps for `problem` on the distro `os_release` describes, or `None`
/// when there is no fix in the table for it. `shipped`: Ubuntu's own
/// [`SHIPPED_BWRAP_PROFILE`] exists, so it is loaded rather than a second
/// `profile bwrap` written next to it.
#[must_use]
pub fn steps(problem: Problem, os_release: &str, shipped: bool) -> Option<&'static [Step]> {
    match problem {
        Problem::AppArmorUserns if shipped => Some(APPARMOR_SHIPPED),
        Problem::AppArmorUserns => Some(APPARMOR),
        Problem::BwrapMissing | Problem::DbusProxyMissing => {
            let ids: Vec<&str> = os_release
                .lines()
                .filter_map(|l| l.strip_prefix("ID=").or_else(|| l.strip_prefix("ID_LIKE=")))
                .flat_map(|v| v.trim_matches(['"', '\'']).split_whitespace())
                .collect();
            let any = |names: &[&str]| ids.iter().any(|id| names.contains(id));
            let dbus = problem == Problem::DbusProxyMissing;
            if any(&["debian", "ubuntu"]) {
                Some(if dbus { APT_DBUS_PROXY } else { APT })
            } else if any(&["fedora", "rhel", "centos"]) {
                Some(if dbus { DNF_DBUS_PROXY } else { DNF })
            } else {
                None
            }
        }
    }
}

/// Why the fix is shown but not offered, or `None` when it may be offered.
#[must_use]
pub fn refusal(
    yes: bool,
    inspect: bool,
    tty: bool,
    env_set: &dyn Fn(&str) -> bool,
) -> Option<&'static str> {
    if env_set("__CPLT_WRAPPED") {
        Some("this is inside a cplt sandbox")
    } else if inspect {
        Some("--print-profile only inspects")
    } else if yes {
        Some("--yes is set")
    } else if env_set("CI") {
        Some("CI is set")
    } else if !tty {
        Some("this is not an interactive terminal")
    } else {
        None
    }
}

/// Root-owned dirs the fixed commands are resolved from; never `PATH`.
const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// `name` from [`SYSTEM_DIRS`], or `None`.
fn system_binary(name: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    SYSTEM_DIRS.iter().map(|d| format!("{d}/{name}")).find(|p| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// A step's argv with every program absolute: `sudo` and the command it
/// runs. `None` when either is missing from [`SYSTEM_DIRS`].
fn resolved(step: &Step, find: &dyn Fn(&str) -> Option<String>) -> Result<Vec<String>, String> {
    step.argv
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if i < 2 {
                find(a).ok_or_else(|| format!("{a} is not in {}", SYSTEM_DIRS.join(", ")))
            } else {
                Ok((*a).to_string())
            }
        })
        .collect()
}

/// The commands as they will run, with any file content in full: the
/// prompt never relies on a diagnostic printed (or skipped) before it.
fn render(steps: &[Step], find: &dyn Fn(&str) -> Option<String>) -> String {
    steps
        .iter()
        .map(|s| {
            let cmd = resolved(s, find).map_or_else(|_| s.argv.join(" "), |a| a.join(" "));
            match s.stdin {
                Some(body) => format!("  {cmd} >/dev/null <<'EOF'\n{body}EOF\n"),
                None => format!("  {cmd}\n"),
            }
        })
        .collect()
}

/// Whether an answer to "[Y/n]" is a yes: only "", "y" or "yes". `None`
/// (end of input, a read error) and anything else is a no.
fn consents(answer: Option<&str>) -> bool {
    answer.is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "" | "y" | "yes"))
}

/// What [`apply`] ended with.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Fixed,
    NotFixed,
    Declined,
}

/// The state file a launch-time decline is remembered in, per cplt version.
fn decline_file(home: &std::path::Path) -> std::path::PathBuf {
    crate::sandbox::cplt_state_file(home, "host-fix-declined")
}

/// Show the fix for `problem`, and on an interactive host offer to run it,
/// then re-check with `recheck` (the launch's own bubblewrap probe).
/// `inspect`: `--print-profile`, which shows the commands and runs nothing.
/// `remember`: a launch, whose "no" is remembered for this cplt version
/// under that home, so the next launch only prints a one-line hint;
/// `cplt doctor --fix` always asks. Returns whether the problem is gone.
pub fn offer(
    problem: Problem,
    yes: bool,
    inspect: bool,
    remember: Option<&std::path::Path>,
    recheck: &dyn Fn() -> bool,
) -> bool {
    let version = env!("CARGO_PKG_VERSION");
    if let Some(home) = remember
        && std::fs::read_to_string(decline_file(home)).is_ok_and(|v| v.trim() == version)
    {
        eprintln!(
            "A host fix is available; you declined it before. Run `cplt doctor --fix` to apply it."
        );
        return false;
    }
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let shipped = std::path::Path::new(SHIPPED_BWRAP_PROFILE).exists();
    let existing = std::fs::read_to_string(PROFILE_PATH).ok();
    let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let why = refusal(yes, inspect, tty, &|k| std::env::var_os(k).is_some());
    let ask = || {
        eprint!("Fix now? sudo will ask for your password. [Y/n] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        let read = match std::io::stdin().read_line(&mut answer) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(answer.as_str()),
        };
        consents(read)
    };
    let (outcome, text) = apply(
        problem.tool(),
        steps(problem, &os_release, shipped),
        why,
        existing.as_deref(),
        &system_binary,
        ask,
        run,
        recheck,
    );
    eprint!("{text}");
    if outcome == Outcome::Declined
        && let Some(home) = remember
    {
        let file = decline_file(home);
        let _ = file.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(file, version);
    }
    outcome == Outcome::Fixed
}

/// [`offer`] with its terminal, lookups, runner and re-check passed in.
/// `existing`: the current content of the profile a step overwrites.
#[allow(clippy::too_many_arguments)] // the tool name plus the injected seams
fn apply(
    what: &str,
    steps: Option<&[Step]>,
    refused: Option<&str>,
    existing: Option<&str>,
    find: &dyn Fn(&str) -> Option<String>,
    ask: impl FnOnce() -> bool,
    mut run: impl FnMut(&[String], Option<&str>) -> Result<(), String>,
    recheck: impl FnOnce() -> bool,
) -> (Outcome, String) {
    let Some(steps) = steps else {
        return (
            Outcome::NotFixed,
            format!("No automatic fix for this distribution: install {what} from its packages.\n"),
        );
    };
    let mut shown = format!("The fix:\n{}", render(steps, find));
    if let Some(old) = existing
        && steps
            .iter()
            .any(|s| s.argv.contains(&PROFILE_PATH) && s.stdin.is_some())
    {
        let nl = if old.ends_with('\n') { "" } else { "\n" };
        shown = format!(
            "{shown}{PROFILE_PATH} exists and will be overwritten. Its content now:\n{old}{nl}"
        );
    }
    if let Some(why) = refused {
        return (
            Outcome::NotFixed,
            format!("{shown}Not offering to run it ({why}). Run the commands above yourself.\n"),
        );
    }
    eprint!("{shown}");
    if !ask() {
        return (Outcome::Declined, "Not fixed.\n".into());
    }
    for step in steps {
        let argv = match resolved(step, find) {
            Ok(a) => a,
            Err(e) => return (Outcome::NotFixed, format!("{e}. Not fixed.\n")),
        };
        if let Err(e) = run(&argv, step.stdin) {
            return (
                Outcome::NotFixed,
                format!("`{}` failed: {e}. Not fixed.\n", argv.join(" ")),
            );
        }
    }
    if recheck() {
        (Outcome::Fixed, format!("Fixed: {what} now starts.\n"))
    } else {
        (
            Outcome::NotFixed,
            format!("The commands ran, but {what} still does not start. Run `cplt doctor`.\n"),
        )
    }
}

/// Run one resolved step: an empty environment but a fixed `PATH`, so
/// nothing from the caller's environment reaches sudo.
fn run(argv: &[String], stdin: Option<&str>) -> Result<(), String> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    #[allow(clippy::disallowed_methods)] // absolute, from SYSTEM_DIRS
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    if stdin.is_some() {
        cmd.stdin(Stdio::piped()).stdout(Stdio::null());
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let (Some(body), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(status.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fix_table() {
        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
        let mint = "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n";
        let fedora = "ID=fedora\n";
        let rocky = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n";
        let arch = "ID=arch\n";
        let missing = |os| steps(Problem::BwrapMissing, os, false);
        assert_eq!(
            steps(Problem::DbusProxyMissing, "ID=ubuntu\n", false),
            Some(APT_DBUS_PROXY)
        );
        assert_eq!(
            steps(Problem::DbusProxyMissing, "ID=fedora\n", false),
            Some(DNF_DBUS_PROXY)
        );
        assert_eq!(missing(ubuntu), Some(APT));
        assert_eq!(missing(mint), Some(APT));
        assert_eq!(missing(fedora), Some(DNF));
        assert_eq!(missing(rocky), Some(DNF));
        assert_eq!(missing(arch), None);
        assert_eq!(missing(""), None);
        assert_eq!(steps(Problem::AppArmorUserns, arch, false), Some(APPARMOR));
        // Ubuntu's own profile is loaded, never a second `profile bwrap`.
        let shipped = steps(Problem::AppArmorUserns, ubuntu, true).unwrap();
        assert_eq!(shipped, APPARMOR_SHIPPED);
        assert!(shipped.iter().all(|s| s.stdin.is_none()));
        // Every command goes through sudo; nothing else is ever run.
        for s in [APT, DNF, APPARMOR, APPARMOR_SHIPPED]
            .iter()
            .flat_map(|s| s.iter())
        {
            assert_eq!(s.argv[0], "sudo", "{s:?}");
        }
    }

    fn fake(name: &str) -> Option<String> {
        (name != "missing").then(|| format!("/usr/bin/{name}"))
    }

    #[test]
    fn commands_are_shown_absolute_with_the_file_in_full() {
        let text = render(APPARMOR, &fake);
        assert_eq!(
            text,
            format!(
                "  /usr/bin/sudo /usr/bin/tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'\n\
                 {APPARMOR_BWRAP_PROFILE}EOF\n  \
                 /usr/bin/sudo /usr/bin/apparmor_parser -r /etc/apparmor.d/bwrap\n"
            )
        );
        assert!(
            text.contains("  userns,\n"),
            "the profile is in the prompt itself"
        );
        assert_eq!(
            render(APT, &fake),
            "  /usr/bin/sudo /usr/bin/apt-get install -y bubblewrap\n"
        );
        // The doctor text a user copies and the table agree.
        assert!(crate::doctor::APPARMOR_BWRAP_FIX.contains(APPARMOR_BWRAP_PROFILE));
    }

    #[test]
    fn only_empty_y_and_yes_consent() {
        for yes in ["", "\n", "y", "Y\n", "yes", " YES \n"] {
            assert!(consents(Some(yes)), "{yes:?}");
        }
        for no in ["n", "N\n", "no", "q", "yep", "nope", "x\n"] {
            assert!(!consents(Some(no)), "{no:?}");
        }
        assert!(!consents(None), "end of input is a no");
    }

    #[test]
    fn offered_only_interactively_and_on_the_host() {
        let none = |_: &str| false;
        assert_eq!(refusal(false, false, true, &none), None);
        assert!(
            refusal(false, true, true, &none)
                .unwrap()
                .contains("--print-profile")
        );
        assert!(refusal(true, false, true, &none).unwrap().contains("--yes"));
        assert!(
            refusal(false, false, false, &none)
                .unwrap()
                .contains("terminal")
        );
        assert!(
            refusal(false, false, true, &|k| k == "CI")
                .unwrap()
                .contains("CI")
        );
        let sandboxed = |k: &str| k == "__CPLT_WRAPPED";
        assert!(
            refusal(false, false, true, &sandboxed)
                .unwrap()
                .contains("sandbox")
        );
    }

    #[test]
    fn problems_from_the_bwrap_state() {
        let unusable = Bubblewrap::Unusable {
            path: "/usr/bin/bwrap".into(),
            reason: "x".into(),
        };
        assert_eq!(
            problem(&Bubblewrap::NotInstalled, false),
            Some(Problem::BwrapMissing)
        );
        assert_eq!(problem(&unusable, true), Some(Problem::AppArmorUserns));
        assert_eq!(problem(&unusable, false), None);
        assert_eq!(problem(&Bubblewrap::Disabled, true), None);
    }

    type Ran = std::cell::RefCell<Vec<String>>;
    fn runner(ran: &Ran) -> impl FnMut(&[String], Option<&str>) -> Result<(), String> + '_ {
        |argv, _| {
            ran.borrow_mut().push(argv.join(" "));
            Ok(())
        }
    }
    fn never(_: &[String], _: Option<&str>) -> Result<(), String> {
        panic!("ran without consent")
    }

    #[test]
    fn apply_runs_the_table_only_after_yes() {
        let ran = Ran::default();
        let (out, text) = apply(
            "bubblewrap",
            Some(APPARMOR),
            None,
            None,
            &fake,
            || true,
            runner(&ran),
            || true,
        );
        assert_eq!(out, Outcome::Fixed, "{text}");
        assert_eq!(
            *ran.borrow(),
            [
                "/usr/bin/sudo /usr/bin/tee /etc/apparmor.d/bwrap",
                "/usr/bin/sudo /usr/bin/apparmor_parser -r /etc/apparmor.d/bwrap"
            ]
        );

        let (out, text) = apply(
            "bubblewrap",
            Some(APT),
            Some("--yes is set"),
            None,
            &fake,
            || panic!("asked"),
            never,
            || true,
        );
        assert_eq!(out, Outcome::NotFixed);
        assert!(
            text.contains("apt-get install -y bubblewrap") && text.contains("--yes"),
            "{text}"
        );
        let (out, text) = apply(
            "bubblewrap",
            Some(APT),
            None,
            None,
            &fake,
            || false,
            never,
            || true,
        );
        assert_eq!(out, Outcome::Declined);
        assert!(text.contains("Not fixed"));
        let (out, _) = apply(
            "bubblewrap",
            None,
            None,
            None,
            &fake,
            || panic!("asked"),
            never,
            || true,
        );
        assert_eq!(out, Outcome::NotFixed);
    }

    #[test]
    fn apply_names_an_overwritten_profile_and_refuses_unresolved_commands() {
        let (_, text) = apply(
            "bubblewrap",
            Some(APPARMOR),
            Some("CI is set"),
            Some("profile old {}\n"),
            &fake,
            || panic!(),
            never,
            || true,
        );
        assert!(text.contains("/etc/apparmor.d/bwrap exists and will be overwritten. Its content now:\nprofile old {}\n"), "{text}");
        let (_, text) = apply(
            "bubblewrap",
            Some(APT),
            Some("CI is set"),
            Some("old"),
            &fake,
            || panic!(),
            never,
            || true,
        );
        assert!(
            !text.contains("overwritten"),
            "apt does not touch the profile: {text}"
        );

        let none = |_: &str| None;
        let (out, text) = apply(
            "bubblewrap",
            Some(APT),
            None,
            None,
            &none,
            || true,
            never,
            || panic!("rechecked"),
        );
        assert_eq!(out, Outcome::NotFixed);
        assert!(
            text.contains("sudo is not in /usr/sbin, /sbin, /usr/bin, /bin"),
            "{text}"
        );
    }

    #[test]
    fn apply_stops_at_a_failed_step_and_reports_a_failed_recheck() {
        let ran = std::cell::Cell::new(0);
        let fail = |_: &[String], _: Option<&str>| {
            ran.set(ran.get() + 1);
            Err("exit status: 1".to_string())
        };
        let (out, text) = apply(
            "bubblewrap",
            Some(APPARMOR),
            None,
            None,
            &fake,
            || true,
            fail,
            || panic!("rechecked"),
        );
        assert_eq!(out, Outcome::NotFixed);
        assert!(
            ran.get() == 1
                && text.contains("`/usr/bin/sudo /usr/bin/tee /etc/apparmor.d/bwrap` failed"),
            "{text}"
        );
        let ok = |_: &[String], _: Option<&str>| Ok(());
        let (out, text) = apply(
            "bubblewrap",
            Some(APT),
            None,
            None,
            &fake,
            || true,
            ok,
            || false,
        );
        assert_eq!(out, Outcome::NotFixed);
        assert!(text.contains("still does not start"));
    }
}
