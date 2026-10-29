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
    /// The host login lives in the OS keychain: on Linux the child gets the
    /// session bus to reach the Secret Service.
    pub keychain: bool,
    /// Under `HOME`, the only places the macOS child sandbox lets the server
    /// write, besides its temp dir: its own config (a refreshed login).
    pub write_dirs: &'static [&'static str],
    /// The same for the Linux child (bwrap), under `XDG_CONFIG_HOME`
    /// (default `~/.config`); the rest of the filesystem is read-only.
    pub linux_write_dirs: &'static [&'static str],
    /// Linux: the child's `HOME` is an empty tmpfs; these paths under it are
    /// bound back read-only, besides `linux_write_dirs`. Only what the
    /// server reads: anything else in `HOME` (a Docker socket, say) stays
    /// out of its reach.
    pub linux_read_paths: &'static [&'static str],
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
        keychain: true,
        // os.UserConfigDir on macOS: nais-credentials.json.enc.
        write_dirs: &["Library/Application Support/nais"],
        // os.UserConfigDir on Linux.
        linux_write_dirs: &["nais"],
        // None. Found by reading nais/cli (dbbfe2e, 2026-10-29) for
        // `alpha mcp serve` and `auth print-access-token -n`: naistrix reads
        // `$XDG_CONFIG_HOME/nais/config.yaml`, the login is
        // `nais-credentials.json.enc` beside it (both in the write dir), its
        // key is in the Secret Service (the bus), and the issuer and console
        // host come from built-in defaults, env and that file. Neither path
        // touches kubeconfig, gcloud or anything else in HOME.
        linux_read_paths: &[],
    },
    // A server with no host login: nothing to probe, any trusted command.
    // Not emitted by nav-pilot today; the broker e2e tests run on it.
    Credential {
        name: "none",
        command: None,
        probe: None,
        keychain: false,
        write_dirs: &[],
        linux_write_dirs: &[],
        linux_read_paths: &[],
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
    if cfg!(target_os = "linux") {
        return sandboxed_probe(spec, args, PROBE_TIMEOUT);
    }
    probe(&spec.program, args, spec.credential.keychain, PROBE_TIMEOUT)
}

/// Linux: the probe in the server's own sandbox (#849). The server can write
/// its config dir, and nais reads `config.yaml` there on every run: its
/// values set any flag, so a planted `nais: false` would turn the probe into
/// a gcloud call. Run on the host, the probe would act on what the
/// sandboxed server wrote. Here it gets the same bwrap namespace, filtered
/// bus and egress proxy, through a broker serving this one spec.
fn sandboxed_probe(
    spec: &Spec,
    args: &[&str],
    timeout: Duration,
) -> (Option<bool>, Option<&'static str>) {
    let Some(home) = std::env::var_os("HOME") else {
        return (None, Some("HOME is not set"));
    };
    let log = super::Log {
        level: crate::proxy::ProxyLogLevel::None,
        file: None,
    };
    let Ok(broker) = super::Broker::start(vec![spec.clone()], std::path::Path::new(&home), log)
    else {
        return (None, Some("cannot start the probe's sandbox"));
    };
    let Ok(child) = broker.spawn_probe(&spec.id, args) else {
        return (None, Some("cannot run the probe"));
    };
    wait(child, timeout)
}

fn probe(
    program: &std::path::Path,
    args: &[&str],
    keychain: bool,
    timeout: Duration,
) -> (Option<bool>, Option<&'static str>) {
    #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load
    let mut cmd = Command::new(program);
    // The child's own environment (#838), so the probe finds the login
    // exactly when the server would.
    // No HOME, no probe: never cplt's own env and the project as cwd.
    let Some(home) = std::env::var_os("HOME") else {
        return (None, Some("HOME is not set"));
    };
    super::runtime::host_env(&mut cmd, std::path::Path::new(&home), keychain);
    cmd.current_dir("/");
    let Ok(child) = cmd
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return (None, Some("cannot run the probe"));
    };
    wait(child, timeout)
}

/// The probe's answer: its exit status, or unknown past `timeout`.
fn wait(mut child: std::process::Child, timeout: Duration) -> (Option<bool>, Option<&'static str>) {
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
        // Through the probe, against a fake nais that is logged in only for
        // the `-n` (nais) token and not for the bare (gcloud) one.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let nais = dir.path().join("nais");
        let staging = dir.path().join("nais.staging");
        std::fs::write(
            &staging,
            "#!/bin/sh\n[ \"$*\" = \"auth print-access-token -n\" ]\n",
        )
        .unwrap();
        // `cp`, not a direct write: see the ETXTBSY note in agent.rs.
        #[allow(clippy::disallowed_methods)]
        let copied = Command::new("/bin/cp").arg(&staging).arg(&nais).status();
        assert!(copied.unwrap().success());
        std::fs::set_permissions(&nais, std::fs::Permissions::from_mode(0o755)).unwrap();
        let m = Credential::parse("nais-keychain").unwrap();
        let long = Duration::from_secs(30);
        let got = crate::with_env_lock_no_xdg(|| probe(&nais, m.probe.unwrap(), m.keychain, long));
        assert_eq!(got, (Some(true), None));
        let gcloud = crate::with_env_lock_no_xdg(|| {
            probe(&nais, &["auth", "print-access-token"], true, long)
        });
        assert_eq!(gcloud, (Some(false), None), "the fake must tell them apart");
    }

    /// #849: on Linux the probe runs in the server's sandbox, so it sees
    /// the child's empty, read-only HOME (when HOME is not under /tmp),
    /// never the host's, and acts on nothing the host keeps there.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_linux_probe_runs_in_the_servers_sandbox() {
        if crate::sandbox::bubblewrap_probe::check_availability().is_none() {
            return;
        }
        let mut spec = super::super::test_util::check(super::super::test_util::base()).unwrap();
        spec.program = "/bin/sh".into();
        // Not under /tmp, whose HOME is private anyway.
        let home = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        std::fs::write(home.path().join("host-file"), "").unwrap();
        // Inside: only the nais config dir, and read-only; the host file is
        // the control.
        let script = r#"[ "$(ls -A "$HOME")" = .config ] || exit 2; ! : > "$HOME/x" 2>/dev/null"#;
        let got = crate::with_env_lock_no_xdg(|| {
            temp_env::with_var("HOME", Some(home.path()), || {
                sandboxed_probe(&spec, &["-c", script], Duration::from_secs(30))
            })
        });
        assert_eq!(got, (Some(true), None));
        assert!(!home.path().join("x").exists());
    }

    #[test]
    fn no_home_no_probe() {
        // Without HOME the probe would run with cplt's whole env and cwd.
        let sh = std::path::Path::new("/bin/sh");
        let r = temp_env::with_var_unset("HOME", || {
            probe(sh, &["-c", "exit 0"], false, Duration::from_secs(30))
        });
        assert_eq!(r, (None, Some("HOME is not set")));
    }

    #[test]
    fn a_probe_timeout_is_unknown_not_logged_out() {
        // HOME stays put: another test unsets it.
        crate::with_env_lock_no_xdg(|| {
            let sh = std::path::Path::new("/bin/sh");
            let short = Duration::from_millis(200);
            assert_eq!(
                probe(sh, &["-c", "sleep 5"], false, short),
                (None, Some("timed out"))
            );
            // Generous: a spawn can stall for seconds under load.
            let long = Duration::from_secs(30);
            assert_eq!(
                probe(sh, &["-c", "exit 1"], false, long),
                (Some(false), None)
            );
            assert_eq!(
                probe(sh, &["-c", "exit 0"], false, long),
                (Some(true), None)
            );
        });
    }
}
