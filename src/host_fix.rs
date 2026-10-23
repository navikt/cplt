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
#[must_use]
pub fn launch_problem() -> Option<Problem> {
    #[cfg(target_os = "linux")]
    {
        if crate::sandbox::bubblewrap_probe::check_availability().is_none() {
            return Some(Problem::BwrapMissing);
        }
        if crate::doctor::apparmor_restricts_userns() && !recheck() {
            return Some(Problem::AppArmorUserns);
        }
    }
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
        Problem::BwrapMissing => {
            let ids: Vec<&str> = os_release
                .lines()
                .filter_map(|l| l.strip_prefix("ID=").or_else(|| l.strip_prefix("ID_LIKE=")))
                .flat_map(|v| v.trim_matches(['"', '\'']).split_whitespace())
                .collect();
            let any = |names: &[&str]| ids.iter().any(|id| names.contains(id));
            if any(&["debian", "ubuntu"]) {
                Some(APT)
            } else if any(&["fedora", "rhel", "centos"]) {
                Some(DNF)
            } else {
                None
            }
        }
    }
}

/// Why the fix is shown but not offered, or `None` when it may be offered.
#[must_use]
pub fn refusal(yes: bool, tty: bool, env_set: &dyn Fn(&str) -> bool) -> Option<&'static str> {
    if env_set("__CPLT_WRAPPED") {
        Some("this is inside a cplt sandbox")
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

/// The commands as a user would type them, with any file content in full.
#[must_use]
pub fn render(steps: &[Step]) -> String {
    steps
        .iter()
        .map(|s| {
            let cmd = s.argv.join(" ");
            match s.stdin {
                Some(body) => format!("  {cmd} >/dev/null <<'EOF'\n{body}EOF\n"),
                None => format!("  {cmd}\n"),
            }
        })
        .collect()
}

/// Show the fix for `problem`, and on an interactive host offer to run it,
/// then re-check. Returns whether the problem is now gone.
pub fn offer(problem: Problem, yes: bool) -> bool {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let shipped = std::path::Path::new(SHIPPED_BWRAP_PROFILE).exists();
    let tty = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let why = refusal(yes, tty, &|k| std::env::var_os(k).is_some());
    let ask = || {
        eprint!("Fix now? sudo will ask for your password. [Y/n] ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).is_ok()
            && !matches!(answer.trim().to_lowercase().as_str(), "n" | "no")
    };
    let (ok, text) = apply(steps(problem, &os_release, shipped), why, ask, run, recheck);
    eprint!("{text}");
    ok
}

/// [`offer`] with its terminal, runner and re-check passed in. Returns
/// whether the problem is gone, and what to print.
fn apply(
    steps: Option<&[Step]>,
    refused: Option<&str>,
    ask: impl FnOnce() -> bool,
    mut run: impl FnMut(&Step) -> Result<(), String>,
    recheck: impl FnOnce() -> bool,
) -> (bool, String) {
    let Some(steps) = steps else {
        return (
            false,
            "No automatic fix for this distribution: install bubblewrap from its packages.\n"
                .into(),
        );
    };
    let shown = format!("The fix:\n{}", render(steps));
    if let Some(why) = refused {
        return (
            false,
            format!("{shown}Not offering to run it ({why}). Run the commands above yourself.\n"),
        );
    }
    eprint!("{shown}");
    if !ask() {
        return (false, "Not fixed.\n".into());
    }
    for step in steps {
        if let Err(e) = run(step) {
            return (
                false,
                format!("`{}` failed: {e}. Not fixed.\n", step.argv.join(" ")),
            );
        }
    }
    if recheck() {
        (true, "Fixed: bubblewrap now starts.\n".into())
    } else {
        (
            false,
            "The commands ran, but bubblewrap still does not start. Run `cplt doctor`.\n".into(),
        )
    }
}

fn run(step: &Step) -> Result<(), String> {
    let (program, args) = step.argv.split_first().ok_or("empty command")?;
    // Only root-owned system dirs for sudo, not Homebrew's.
    let path = crate::git::trusted_binary(program)
        .filter(|p| p.starts_with("/usr/bin") || p.starts_with("/bin"))
        .ok_or_else(|| format!("{program} is not in /usr/bin or /bin"))?;
    #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs above
    let mut cmd = Command::new(path);
    cmd.args(args);
    if step.stdin.is_some() {
        cmd.stdin(Stdio::piped()).stdout(Stdio::null());
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let (Some(body), Some(mut stdin)) = (step.stdin, child.stdin.take()) {
        stdin
            .write_all(body.as_bytes())
            .map_err(|e| e.to_string())?;
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(status.to_string())
    }
}

/// bwrap is installed in a trusted dir and can create a user namespace.
fn recheck() -> bool {
    let Some(bwrap) = crate::git::trusted_binary("bwrap") else {
        return false;
    };
    #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs above
    Command::new(bwrap)
        .args(["--unshare-user", "--ro-bind", "/", "/", "/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
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

    #[test]
    fn commands_and_the_file_are_shown_in_full() {
        let text = render(APPARMOR);
        assert!(text.contains("sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'\n"));
        assert!(text.contains(APPARMOR_BWRAP_PROFILE));
        assert!(text.contains("  userns,\n"));
        assert!(text.ends_with("sudo apparmor_parser -r /etc/apparmor.d/bwrap\n"));
        assert_eq!(render(APT), "  sudo apt-get install -y bubblewrap\n");
        // The doctor text a user copies and the table agree.
        assert!(crate::doctor::APPARMOR_BWRAP_FIX.contains(APPARMOR_BWRAP_PROFILE));
    }

    #[test]
    fn offered_only_interactively_and_on_the_host() {
        let none = |_: &str| false;
        assert_eq!(refusal(false, true, &none), None);
        assert!(refusal(true, true, &none).unwrap().contains("--yes"));
        assert!(refusal(false, false, &none).unwrap().contains("terminal"));
        assert!(refusal(false, true, &|k| k == "CI").unwrap().contains("CI"));
        let sandboxed = |k: &str| k == "__CPLT_WRAPPED";
        assert!(
            refusal(false, true, &sandboxed)
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

    #[test]
    fn apply_runs_the_table_only_after_yes() {
        let mut ran = Vec::new();
        let (ok, text) = apply(
            Some(APPARMOR),
            None,
            || true,
            |s| {
                ran.push(s.argv.join(" "));
                Ok(())
            },
            || true,
        );
        assert!(ok, "{text}");
        assert_eq!(
            ran,
            [
                "sudo tee /etc/apparmor.d/bwrap",
                "sudo apparmor_parser -r /etc/apparmor.d/bwrap"
            ]
        );

        let never = |_: &Step| -> Result<(), String> { panic!("ran without consent") };
        let (ok, text) = apply(
            Some(APT),
            Some("--yes is set"),
            || panic!("asked"),
            never,
            || true,
        );
        assert!(
            !ok && text.contains("sudo apt-get install -y bubblewrap") && text.contains("--yes")
        );
        let (ok, text) = apply(Some(APT), None, || false, never, || true);
        assert!(!ok && text.contains("Not fixed"));
        let (ok, _) = apply(None, None, || panic!("asked"), never, || true);
        assert!(!ok);
    }

    #[test]
    fn apply_stops_at_a_failed_step_and_reports_a_failed_recheck() {
        let mut ran = 0;
        let (ok, text) = apply(
            Some(APPARMOR),
            None,
            || true,
            |_| {
                ran += 1;
                Err("exit status: 1".into())
            },
            || panic!("rechecked"),
        );
        assert!(!ok && ran == 1 && text.contains("`sudo tee /etc/apparmor.d/bwrap` failed"));
        let (ok, text) = apply(Some(APT), None, || true, |_| Ok(()), || false);
        assert!(!ok && text.contains("still does not start"));
    }
}
