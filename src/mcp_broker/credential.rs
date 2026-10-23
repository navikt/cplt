//! cplt's credential mechanisms (design section 7): one row per mechanism.
//! Hand-kept; tool policy is never here. A new server on an existing
//! mechanism needs no change; a new mechanism is one row.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Serialize, Serializer};

use super::PROBE_TIMEOUT;
use super::spec::Spec;

/// One credential mechanism.
#[derive(Debug, PartialEq, Eq)]
pub struct Credential {
    /// The spec's `credential` value.
    pub name: &'static str,
    /// The only command a spec with this mechanism may run; `None` allows
    /// any command resolved in the trusted dirs.
    pub command: Option<&'static [&'static str]>,
    /// Arguments to the spec's own program that exit 0 when the host login
    /// is usable (output discarded); `None` when there is nothing to probe.
    pub probe: Option<&'static [&'static str]>,
}

/// The table.
pub const MECHANISMS: &[Credential] = &[
    // nais reads its own keychain item; cplt never touches it. The probe
    // needs -n: without it nais prints the gcloud token, which the MCP
    // server does not use, so an expired gcloud login read as logged out.
    Credential {
        name: "nais-keychain",
        command: Some(&["nais", "alpha", "mcp", "serve"]),
        probe: Some(&["auth", "print-access-token", "-n"]),
    },
    // A server with no host login: nothing to probe, any trusted command.
    // Not emitted by nav-pilot today; the broker e2e tests run on it.
    Credential {
        name: "none",
        command: None,
        probe: None,
    },
];

impl Credential {
    pub(crate) fn parse(name: &str) -> Result<&'static Self, String> {
        if name == "gh-token" {
            return Err(
                "credential gh-token is served by cplt's built-in GitHub MCP proxy, not by a broker spec"
                    .into(),
            );
        }
        MECHANISMS.iter().find(|m| m.name == name).ok_or_else(|| {
            let names: Vec<&str> = MECHANISMS.iter().map(|m| m.name).collect();
            format!(
                "credential {:?} is not a cplt mechanism ({})",
                name.escape_debug().to_string(),
                names.join(", ")
            )
        })
    }
}

impl Serialize for Credential {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name)
    }
}

/// The mechanism's status probe, without printing anything it outputs:
/// whether the login is usable, `None` when unknown, with a note saying why
/// it is unknown. `(None, None)` when the mechanism has no probe.
pub fn credential_ok(spec: &Spec) -> (Option<bool>, Option<&'static str>) {
    let Some(args) = spec.credential.probe else {
        return (None, None);
    };
    probe(&spec.program, args, PROBE_TIMEOUT)
}

fn probe(
    program: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> (Option<bool>, Option<&'static str>) {
    #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load
    let mut cmd = Command::new(program);
    // The child's own environment (#838), so the probe finds the login
    // exactly when the server would.
    if let Some(home) = std::env::var_os("HOME") {
        super::runtime::host_env(&mut cmd, std::path::Path::new(&home));
        cmd.current_dir("/");
    }
    let Ok(mut child) = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return (None, Some("cannot run the probe"));
    };
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return (Some(status.success()), None);
        }
        // A slow keychain or network is not a logged-out user.
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return (None, Some("timed out"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nais_probe_checks_the_nais_login_not_gcloud() {
        let m = Credential::parse("nais-keychain").unwrap();
        assert_eq!(m.probe, Some(&["auth", "print-access-token", "-n"][..]));
    }

    #[test]
    fn a_probe_timeout_is_unknown_not_logged_out() {
        let sh = std::path::Path::new("/bin/sh");
        let short = Duration::from_millis(200);
        assert_eq!(
            probe(sh, &["-c", "sleep 5"], short),
            (None, Some("timed out"))
        );
        // Generous: a spawn can stall for seconds under load.
        let long = Duration::from_secs(30);
        assert_eq!(probe(sh, &["-c", "exit 1"], long), (Some(false), None));
        assert_eq!(probe(sh, &["-c", "exit 0"], long), (Some(true), None));
    }
}
