//! Real command-path checks for the parent-owned CONNECT snapshot.
//! All network endpoints belong to the test. No agent account is required.

mod common;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod tests {
    use super::common::{cplt_cmd, git_cmd};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::process::{Command, Output};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const RECORDED: &str = "Proxy-observed CONNECT attempts recorded:";

    fn project() -> tempfile::TempDir {
        let project = tempfile::Builder::new()
            .prefix(".cplt-e2e-network-")
            .tempdir_in(std::env::current_dir().unwrap())
            .unwrap();
        std::fs::write(project.path().join("tracked.txt"), "baseline\n").unwrap();
        for args in [
            vec!["init", "--quiet"],
            vec!["add", "tracked.txt"],
            vec![
                "-c",
                "user.name=Network fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "baseline",
            ],
        ] {
            let output = git_cmd(project.path()).args(args).output().unwrap();
            assert!(output.status.success(), "{output:?}");
        }
        project
    }

    fn command(project: &tempfile::TempDir) -> Command {
        let mut command = cplt_cmd();
        command
            .current_dir(project.path())
            .env("SHELL", "/bin/sh")
            .env("NO_COLOR", "1")
            .args(["--yes", "--no-validate", "--agent", "shell"]);
        command
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8(output.stderr.clone()).unwrap()
    }

    struct Origin {
        address: SocketAddr,
        worker: Option<JoinHandle<()>>,
    }

    impl Origin {
        fn start() -> Self {
            Self::bind("127.0.0.1:0".parse().unwrap())
        }

        fn bind(address: SocketAddr) -> Self {
            let listener = TcpListener::bind(address).unwrap();
            let address = listener.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                // Drain the headers before closing, so unread client bytes
                // cannot turn a successful response into a TCP reset.
                while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                    let mut byte = [0];
                    // A cleanup connection can wake accept when the child fails.
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    request.push(byte[0]);
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nfixture-ok\n");
            });
            Self {
                address,
                worker: Some(worker),
            }
        }

        fn script(&self) -> String {
            format!(
                "/usr/bin/curl --silent --show-error --max-time 5 --proxytunnel --proxy \"$HTTPS_PROXY\" --noproxy '' http://127.0.0.1:{}/; printf 'command-stdout\\n'; exit 37",
                self.address.port()
            )
        }
    }

    impl Drop for Origin {
        fn drop(&mut self) {
            if let Some(worker) = self.worker.take() {
                if !worker.is_finished() {
                    let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
                }
                let _ = worker.join();
            }
        }
    }

    #[test]
    fn both_execution_paths_report_one_record_and_preserve_child_output_and_status() {
        for exec in [false, true] {
            let project = project();
            let origin = Origin::start();
            let mut command = command(&project);
            command.args([
                "--no-quiet",
                "--allow-localhost",
                &origin.address.port().to_string(),
            ]);
            if exec {
                command.args(["exec", "--", "/bin/sh"]);
            } else {
                command.arg("--");
            }
            let output = command.args(["-c", &origin.script()]).output().unwrap();
            let stderr = stderr(&output);
            assert_eq!(output.status.code(), Some(37), "{stderr}");
            assert_eq!(output.stdout, b"fixture-ok\ncommand-stdout\n", "{stderr}");
            assert!(stderr.contains(&format!("{RECORDED} 1.")), "{stderr}");
            assert_eq!(stderr.matches(RECORDED).count(), 1, "{stderr}");
        }
    }

    #[test]
    fn audit_switch_preserves_forced_proxy_outcomes() {
        for audit in [true, false] {
            let project = project();
            let origin = Origin::start();
            let mut command = command(&project);
            command.args([
                "--no-quiet",
                "--proxy-forced",
                "--allow-localhost",
                &origin.address.port().to_string(),
            ]);
            if !audit {
                command.arg("--no-audit");
            }
            let output = command
                .args(["exec", "--", "/bin/sh", "-c", &origin.script()])
                .output()
                .unwrap();
            let stderr = stderr(&output);
            assert_eq!(output.status.code(), Some(37), "{stderr}");
            assert_eq!(output.stdout, b"fixture-ok\ncommand-stdout\n", "{stderr}");
            assert_eq!(stderr.contains(RECORDED), audit, "{stderr}");
        }
    }

    #[test]
    fn audit_switch_preserves_blocked_connect_outcomes() {
        let mut blocked_status = None;
        for audit in [true, false] {
            let project = project();
            let allowlist = project.path().join("allowed-domains.txt");
            std::fs::write(&allowlist, "permitted.example.invalid\n").unwrap();
            let mut command = command(&project);
            command
                .args(["--no-quiet", "--proxy-forced", "--allowed-domains"])
                .arg(&allowlist);
            if !audit {
                command.arg("--no-audit");
            }
            let output = command
                .args([
                    "exec", "--", "/bin/sh", "-c",
                    "/usr/bin/curl --silent --show-error --max-time 5 --proxy \"$HTTPS_PROXY\" --noproxy '' https://blocked.example.invalid/",
                ])
                .output()
                .unwrap();
            let stderr = stderr(&output);
            assert!(!output.status.success(), "{stderr}");
            if let Some(expected) = blocked_status {
                assert_eq!(output.status.code(), Some(expected), "{stderr}");
            } else {
                blocked_status = output.status.code();
                assert!(blocked_status.is_some(), "{stderr}");
            }
            assert!(output.stdout.is_empty(), "{output:?}");
            assert!(stderr.contains("403"), "{stderr}");
            assert_eq!(stderr.contains(RECORDED), audit, "{stderr}");
            if audit {
                assert!(stderr.contains(&format!("{RECORDED} 1.")), "{stderr}");
                assert!(
                    stderr.contains("Hosts with blocked activity: 1."),
                    "{stderr}"
                );
            }
        }
    }

    #[test]
    fn disabled_proxy_is_unavailable_instead_of_zero() {
        let project = project();
        let output = command(&project)
            .args([
                "--no-quiet",
                "--no-proxy",
                "exec",
                "--",
                "/bin/sh",
                "-c",
                "printf 'child-only\\n'; exit 41",
            ])
            .output()
            .unwrap();
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(41), "{stderr}");
        assert_eq!(output.stdout, b"child-only\n");
        assert!(
            stderr.contains("Network observations unavailable"),
            "{stderr}"
        );
        assert!(!stderr.contains(RECORDED), "{stderr}");
    }

    #[test]
    fn quiet_and_audit_controls_suppress_network_report() {
        let project = project();
        for flags in [vec![], vec!["--quiet"], vec!["--no-quiet", "--no-audit"]] {
            let output = command(&project)
                .args(flags)
                .args(["exec", "--", "/bin/sh", "-c", "printf 'child-only\\n'"])
                .output()
                .unwrap();
            let stderr = stderr(&output);
            assert!(output.status.success(), "{stderr}");
            assert_eq!(output.stdout, b"child-only\n");
            assert!(!stderr.contains(RECORDED), "{stderr}");
            assert!(
                !stderr.contains("Network observations unavailable"),
                "{stderr}"
            );
        }
        let config_dir = tempfile::tempdir().unwrap();
        let config = config_dir.path().join("audit-disabled.toml");
        std::fs::write(&config, "[sandbox]\naudit = false\n").unwrap();
        let output = command(&project)
            .env("CPLT_CONFIG", config)
            .args(["--no-quiet", "exec", "--", "/usr/bin/true"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
        assert!(!stderr(&output).contains(RECORDED), "{}", stderr(&output));
    }

    #[test]
    fn quiet_observe_waits_for_descendant_connect() {
        let project = project();
        let origin = Origin::start();
        let mut command = command(&project);
        // Bubblewrap terminates its PID namespace when the direct child exits.
        // Exercise the descendant probe with the supported Landlock-only path.
        #[cfg(target_os = "linux")]
        command.arg("--no-bubblewrap");
        let output = command
            .args([
                "--observe-domains",
                "--allow-localhost",
                &origin.address.port().to_string(),
                "exec",
                "--",
                "/bin/sh",
                "-c",
                &format!(
                    "parent=$$; (while kill -0 \"$parent\" 2>/dev/null; do :; done; {}) & exit 37",
                    origin.script()
                ),
            ])
            .output()
            .unwrap();
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(37), "{stderr}");
        assert_eq!(output.stdout, b"fixture-ok\ncommand-stdout\n", "{stderr}");
        assert!(
            stderr.contains("1 proxy-observed retained CONNECT host"),
            "{stderr}"
        );
        assert!(stderr.contains("classification: settled."), "{stderr}");
        assert!(!stderr.contains(RECORDED), "{stderr}");
    }

    #[test]
    fn quiet_observe_discloses_descendants_after_settle_deadline() {
        let project = project();
        let mut command = command(&project);
        // Bubblewrap terminates its PID namespace when the direct child exits.
        // Exercise the descendant probe with the supported Landlock-only path.
        #[cfg(target_os = "linux")]
        command.arg("--no-bubblewrap");
        let output = command
            .args([
                "--observe-domains",
                "exec",
                "--",
                "/bin/sh",
                "-c",
                "(while [ ! -f release-descendant ]; do :; done; printf done > descendant-done) >/dev/null 2>&1 & exit 37",
            ])
            .output()
            .unwrap();
        std::fs::write(project.path().join("release-descendant"), "release").unwrap();
        let cleanup_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !project.path().join("descendant-done").exists() {
            assert!(
                std::time::Instant::now() < cleanup_deadline,
                "descendant did not acknowledge release"
            );
            std::thread::yield_now();
        }
        let stderr = stderr(&output);
        assert_eq!(output.status.code(), Some(37), "{stderr}");
        assert!(
            stderr.contains("session left processes running"),
            "{stderr}"
        );
        assert!(
            stderr.contains("network activity after the cutoff is excluded"),
            "{stderr}"
        );
        assert!(!stderr.contains(RECORDED), "{stderr}");
    }

    #[test]
    fn available_empty_snapshot_does_not_claim_no_networking() {
        let project = project();
        let output = command(&project)
            .args(["--no-quiet", "exec", "--", "/usr/bin/true"])
            .output()
            .unwrap();
        let stderr = stderr(&output);
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains(&format!("{RECORDED} 0.")), "{stderr}");
        assert!(stderr.contains("does not prove"), "{stderr}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_forced_port_residual_can_transfer_data_without_a_proxy_record() {
        // UDP connect selects the interface address without sending a packet.
        // The HTTP peer then listens on that non-loopback address only, leaving
        // the same port available for the cplt proxy on 127.0.0.1.
        let route = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        route.connect("192.0.2.1:9").unwrap();
        let address = route.local_addr().unwrap().ip();
        assert!(!address.is_loopback() && !address.is_unspecified());
        let origin = Origin::bind(SocketAddr::new(address, 0));
        let project = project();
        let output = command(&project)
            .args([
                "--no-quiet",
                "--proxy-forced",
                "--proxy-port",
                &origin.address.port().to_string(),
                "exec",
                "--",
                "/usr/bin/curl",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--noproxy",
                "*",
                &format!("http://{}/", origin.address),
            ])
            .output()
            .unwrap();
        let stderr = stderr(&output);
        assert!(output.status.success(), "{stderr}");
        assert_eq!(output.stdout, b"fixture-ok\n", "{stderr}");
        assert!(stderr.contains(&format!("{RECORDED} 0.")), "{stderr}");
        assert!(stderr.contains("localhost"), "{stderr}");
        assert!(stderr.contains("does not prove"), "{stderr}");
    }
}
