//! #830: the legacy-state pin is process-wide, so it is tested in its own
//! binary where it cannot leak into the XDG tests in the library.

mod common;

use std::path::PathBuf;

use cplt::sandbox::{CPLT_STATE_DIR, cplt_state_dir, pin_legacy_state_dir_if_inside};

#[test]
fn xdg_inside_allow_write_pins_state_to_the_legacy_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let granted = tmp.path().join("granted");
    let project = tmp.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let xdg = granted.join("cfg");
    let legacy = home.join(CPLT_STATE_DIR);

    // #851: config in the XDG root follows the pin too.
    std::fs::create_dir_all(xdg.join("cplt")).unwrap();
    std::fs::write(xdg.join("cplt/config.toml"), "").unwrap();
    let vars = [
        ("XDG_CONFIG_HOME", Some(xdg.as_os_str())),
        ("HOME", Some(home.as_os_str())),
        ("CPLT_CONFIG", None),
    ];
    temp_env::with_vars(vars, || {
        assert_eq!(cplt_state_dir(&home), xdg.join("cplt"));
        assert_eq!(cplt::config::config_dir(), Some(xdg.join("cplt")));
        let pinned = pin_legacy_state_dir_if_inside(&home, std::slice::from_ref(&granted));
        assert_eq!(pinned, Some((xdg.join("cplt"), granted.clone())));
        assert_eq!(cplt_state_dir(&home), legacy);
        assert_eq!(cplt::config::config_dir(), Some(legacy.clone()));
        assert_eq!(cplt::config::approval_dirs(), vec![legacy.clone()]);
        // Reported once.
        assert_eq!(
            pin_legacy_state_dir_if_inside(&home, &[PathBuf::from(&granted)]),
            None
        );
        // A state read after the pin uses the legacy dir.
        assert!(cplt::launch_state::changed(&home, &project, "nested", "a"));
        assert!(!cplt::launch_state::changed(&home, &project, "nested", "a"));
    });
    assert!(legacy.join("launch").read_dir().unwrap().next().is_some());
    assert!(
        !xdg.join("cplt/launch").exists(),
        "nothing written under the grant"
    );
}

/// Fable: no launch-state read or write before the state dir is validated.
/// The legacy `~/.config/cplt` is linked into a granted tree, so the launch
/// is refused; a planted `launch/<hash>-nested` FIFO must not hang it and a
/// planted symlink must not let it overwrite the target.
#[test]
fn e2e_planted_launch_state_is_never_touched_before_the_refusal() {
    use sha2::{Digest, Sha256};
    use std::time::{Duration, Instant};

    for kind in ["fifo", "symlink"] {
        let home = std::fs::canonicalize(common::make_config_home("state-order")).unwrap();
        let granted = home.join("granted");
        let legacy_target = granted.join("legacy");
        std::fs::create_dir_all(legacy_target.join("launch")).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::os::unix::fs::symlink(&legacy_target, home.join(".config/cplt")).unwrap();
        let project = home.join("project");
        std::fs::create_dir_all(&project).unwrap();
        assert!(common::git_ok(&project, &["init", "-q"]));

        let hash: String = Sha256::digest(project.to_string_lossy().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let planted = legacy_target.join(format!("launch/{}-nested", &hash[..32]));
        let sentinel = home.join("sentinel");
        std::fs::write(&sentinel, "keep").unwrap();
        if kind == "fifo" {
            let c = std::ffi::CString::new(planted.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        } else {
            std::os::unix::fs::symlink(&sentinel, &planted).unwrap();
        }

        let mut child = common::cplt_local(&home, &project)
            .args(["--agent", "copilot", "--yes", "--allow-write"])
            .arg(&granted)
            .env("XDG_CONFIG_HOME", granted.join("xdg"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            if start.elapsed() > Duration::from_secs(30) {
                let _ = child.kill();
                panic!("{kind}: launch hung on the planted launch state");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let mut stderr = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
        assert!(!status.success(), "{kind}: {stderr}");
        // `granted` holds the linked state dir: the ancestor check only warns
        // about that (#1096 follow-up), and the resolved-link check refuses.
        assert!(
            stderr.contains("which is writable in the sandbox"),
            "{kind}: {stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            "keep",
            "{kind}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

/// A launch refused for a grant inside the state dir must not flush or prune
/// state first: maintenance runs only after every refusal has passed (#1095).
/// (This used to pass on the temp dir's grant over the fake account home,
/// which now only warns; `policy_write_into_state_dir_is_refused` covers the
/// policy-level check itself.)
#[test]
fn e2e_policy_refusal_prunes_nothing() {
    let home = std::fs::canonicalize(common::make_config_home("policy-refusal")).unwrap();
    let account = home.join("account");
    std::fs::create_dir_all(account.join(".config/cplt/managed.d")).unwrap();
    let launch = home.join(".config/cplt/launch");
    std::fs::create_dir_all(&launch).unwrap();
    let marker = launch.join("stale-marker");
    let f = std::fs::File::create(&marker).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(400 * 24 * 3600);
    f.set_modified(old).unwrap();
    drop(f);
    let project = home.join("project");
    std::fs::create_dir_all(&project).unwrap();
    assert!(
        common::git_ok(&project, &["init", "-q"]),
        "git init should succeed"
    );

    // Present: a missing socket path is dropped with a warning, not granted.
    let sock = account.join(".config/cplt/managed.d/agent.sock");
    std::fs::write(&sock, "").unwrap();
    let out = common::cplt_local(&home, &project)
        .args(["--agent", "copilot", "--yes", "--allow-socket"])
        .arg(account.join(".config/cplt/managed.d/agent.sock"))
        .env("CPLT_TEST_ACCOUNT_HOME", &account)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("XDG_CACHE_HOME")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "the launch should be refused: {stderr}"
    );
    assert!(
        stderr.contains("inside cplt's own state directory"),
        "the grant inside the state dir should be what refuses: {stderr}"
    );
    assert!(
        marker.exists(),
        "a refused launch must not prune launch records"
    );
    let _ = std::fs::remove_dir_all(&home);
}
