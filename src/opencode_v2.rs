//! OpenCode v2 sessions (#710).
//!
//! v2 runs every tool call in a background service (`opencode serve
//! --service`) that clients find through `$XDG_STATE_HOME/opencode/service.json`
//! and reach on the port named in `$XDG_CONFIG_HOME/opencode/service.json`
//! (default 49374). A host service would run the agent's tools unsandboxed, so
//! each cplt session gets its own:
//!
//! - a private `XDG_STATE_HOME`, so the host service's registration (and its
//!   password) is not found and the client spawns a service of its own. That
//!   service is a descendant of the sandboxed client and inherits the sandbox;
//! - an `XDG_CONFIG_HOME` overlay that links every entry of the user's config
//!   dir, and every entry of its `opencode/`, except the user's `service.json`,
//!   which cplt replaces with one naming a free port and a random password;
//! - a profile tail that opens loopback to that port only and denies both host
//!   `service.json` files.
//!
//! Both dirs live in the session scratch dir. Removing it at exit takes the
//! registration with it, and the service shuts itself down within 5 s when its
//! registration is gone; a crashed session's dir goes with the scratch GC.
//! The database (`$XDG_DATA_HOME/opencode/opencode.db`) stays shared with the
//! host. Overlay entries are a snapshot: a top-level entry the user creates
//! during the session is not seen until the next one.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// What the launch adds for a v2 session.
pub struct Session {
    /// Set on the child after the sandbox's own environment.
    pub env: Vec<(String, String)>,
    /// Appended to the end of the macOS profile (last match wins).
    pub sbpl: String,
}

/// An XDG base from the environment, ignoring a relative or empty value as the
/// spec says, else `$HOME/<default>`.
fn xdg_base(var: &str, home: &Path, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.join(default))
}

/// Set up the session under `scratch` and return its env and profile tail.
pub fn prepare(scratch: &Path, home: &Path, launch_dir: &Path) -> Result<Session, String> {
    let config_base = xdg_base("XDG_CONFIG_HOME", home, ".config");
    let state_base = xdg_base("XDG_STATE_HOME", home, ".local/state");
    // v2 uses OPENCODE_CONFIG_DIR, when set, in place of
    // `$XDG_CONFIG_HOME/opencode`, service.json included.
    let user_oc = std::env::var_os("OPENCODE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| config_base.join("opencode"));
    let config = scratch.join("opencode-v2/config");
    let state = scratch.join("opencode-v2/state");
    std::fs::create_dir_all(&state).map_err(|e| format!("{}: {e}", state.display()))?;
    build_overlay(&config_base, &user_oc, &config)
        .map_err(|e| format!("{}: {e}", config.display()))?;
    let port = free_port().map_err(|e| format!("no free loopback port: {e}"))?;
    let password = crate::scratch::generate_session_id()?;
    let body = serde_json::json!({ "port": port, "password": password }).to_string();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(config.join("opencode/service.json"))
        .and_then(|mut f| f.write_all(body.as_bytes()))
        .map_err(|e| format!("cannot write service.json: {e}"))?;
    let env = vec![
        ("XDG_CONFIG_HOME".into(), config.display().to_string()),
        ("XDG_STATE_HOME".into(), state.display().to_string()),
        (
            "OPENCODE_CONFIG_DIR".into(),
            config.join("opencode").display().to_string(),
        ),
        ("OPENCODE_DISABLE_MODELS_FETCH".into(), "1".into()),
        ("OPENCODE_DISABLE_AUTOUPDATE".into(), "1".into()),
    ];
    let files = [
        user_oc.join("service.json"),
        config_base.join("opencode/service.json"),
        state_base.join("opencode/service.json"),
    ];
    Ok(Session {
        env,
        sbpl: profile_tail(home, launch_dir, &files, port)?,
    })
}

/// `overlay` = a link per entry of `user`, except `opencode`, which becomes a
/// real dir holding a link per entry of `user_oc` except `service.json`.
fn build_overlay(user: &Path, user_oc: &Path, overlay: &Path) -> std::io::Result<()> {
    let own = overlay.join("opencode");
    std::fs::create_dir_all(&own)?;
    for (from, to, skip) in [(user, overlay, "opencode"), (user_oc, &own, "service.json")] {
        let Ok(entries) = std::fs::read_dir(from) else {
            continue;
        };
        for e in entries.flatten() {
            if e.file_name() != skip {
                std::os::unix::fs::symlink(e.path(), to.join(e.file_name()))?;
            }
        }
    }
    Ok(())
}

/// ponytail: the port is released before the service binds it, so another
/// process can take it in between; the service then fails "already in use"
/// after its 15 s retry. Rare; passing a bound socket in would need upstream.
fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// The SBPL rules a v2 session adds.
///
/// v2's config discovery resolves `$HOME` and every parent of the working dir,
/// plus the `.claude`, `.agents` and `.opencode` entries in each, and treats
/// any error other than "not found" as fatal. Those dir entries themselves
/// become readable (a listing of names), at the spelled and the resolved
/// path; their contents stay denied. An existing `opencode.json(c)` there
/// is a config v2 loads, so a plain one is readable.
///
/// The host `service.json` files are denied at the spelled and the resolved
/// path. Every ancestor is pinned against unlink, so a writable one (the
/// granted host state dir) cannot be renamed into a readable tree to carry
/// the file out from under the literal deny.
fn profile_tail(
    home: &Path,
    launch_dir: &Path,
    files: &[PathBuf],
    port: u16,
) -> Result<String, String> {
    let mut denied = Vec::new();
    for file in files {
        // Resolved per file, so a symlinked `opencode/` dir is covered too.
        denied.extend([file.clone(), crate::config::canonicalize_deepest(file)]);
    }
    denied.sort();
    denied.dedup();
    let mut pinned: Vec<PathBuf> = denied
        .iter()
        .flat_map(|f| f.ancestors().skip(1).map(Path::to_path_buf))
        .collect();
    pinned.sort();
    pinned.dedup();
    let mut reads = Vec::new();
    for dir in home.ancestors().chain(launch_dir.ancestors()) {
        reads.push(dir.to_path_buf());
        for name in [".claude", ".agents", ".opencode"] {
            let entry = dir.join(name);
            if let Ok(real) = std::fs::canonicalize(&entry) {
                reads.push(real);
            }
            reads.push(entry);
        }
        // Discovery also resolves each `opencode.json(c)` and reads it as a
        // config (#718). Granted only as a plain file with one link: a symlink
        // or a hard link the agent planted could name any file, ~/.ssh too.
        // Anything else is refused by name rather than left to fail as EPERM.
        for name in ["opencode.json", "opencode.jsonc"] {
            let file = dir.join(name);
            let Ok(m) = std::fs::symlink_metadata(&file) else {
                continue;
            };
            if !(m.is_file() && m.nlink() == 1) {
                return Err(format!(
                    "{} is a symlink, hard link or directory. OpenCode v2 reads it as \
                     config, and cplt grants it only as a plain file. Replace it with a \
                     regular file or move it.",
                    file.display()
                ));
            }
            reads.extend(std::fs::canonicalize(&file));
            reads.push(file);
        }
    }
    reads.sort();
    reads.dedup();
    for p in reads.iter().chain(&denied).chain(&pinned) {
        crate::sandbox::validate_sbpl_path(p)?;
    }
    let lit = |ps: &[PathBuf]| {
        ps.iter()
            .map(|p| format!(" (literal \"{}\")", p.display()))
            .collect::<String>()
    };
    Ok(format!(
        "\n;; OpenCode v2 session service (#710)\n\
         (allow file-read-data{})\n\
         (deny file-read* file-write*{})\n\
         (deny file-write-unlink{})\n\
         (allow network-outbound (remote ip \"localhost:{port}\"))\n",
        lit(&reads),
        lit(&denied),
        lit(&pinned),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_links_everything_but_the_service_files() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp.path().join("user");
        std::fs::create_dir_all(user.join("opencode/agent")).unwrap();
        std::fs::create_dir_all(user.join("git")).unwrap();
        std::fs::write(user.join("opencode/opencode.json"), "{}").unwrap();
        std::fs::write(user.join("opencode/service.json"), "{\"password\":\"x\"}").unwrap();
        let ov = tmp.path().join("ov");
        build_overlay(&user, &user.join("opencode"), &ov).unwrap();
        assert_eq!(
            std::fs::read_link(ov.join("git")).unwrap(),
            user.join("git")
        );
        assert!(!ov.join("opencode").is_symlink());
        for e in ["agent", "opencode.json"] {
            assert_eq!(
                std::fs::read_link(ov.join("opencode").join(e)).unwrap(),
                user.join("opencode").join(e)
            );
        }
        assert!(!ov.join("opencode/service.json").exists());
        // A user without a config dir still gets the overlay.
        let missing = tmp.path().join("missing");
        build_overlay(&missing, &missing.join("opencode"), &tmp.path().join("ov2")).unwrap();
        assert!(tmp.path().join("ov2/opencode").is_dir());
    }

    /// A dotfiles-style symlinked `opencode/` dir: the resolved file is denied.
    #[test]
    fn service_json_is_denied_at_its_resolved_path() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join("dotfiles/opencode")).unwrap();
        std::fs::create_dir_all(root.join("cfg")).unwrap();
        std::os::unix::fs::symlink(root.join("dotfiles/opencode"), root.join("cfg/opencode"))
            .unwrap();
        let tail =
            profile_tail(&root, &root, &[root.join("cfg/opencode/service.json")], 1).unwrap();
        for f in [
            "cfg/opencode/service.json",
            "dotfiles/opencode/service.json",
        ] {
            assert!(
                tail.contains(&format!("(literal \"{}\")", root.join(f).display())),
                "{f}"
            );
        }
    }

    /// Kernel check: the writable host state dir cannot be renamed away to
    /// carry `service.json` out from under its literal deny, and the file
    /// itself cannot be read. Control: without the tail the rename works.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin/sandbox-exec, /bin tools
    fn host_service_json_survives_a_rename_of_its_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let state = root.join("state/opencode");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(root.join("proj")).unwrap();
        std::fs::write(state.join("service.json"), "{}").unwrap();
        let tail = profile_tail(&root, &root, &[state.join("service.json")], 1).unwrap();
        let run = |profile: &str, cmd: &[&str]| {
            std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", profile])
                .args(cmd)
                .output()
                .unwrap()
                .status
                .success()
        };
        let guarded = format!("(version 1)(allow default){tail}");
        let moved = root.join("proj/moved");
        let mv = ["/bin/mv", state.to_str().unwrap(), moved.to_str().unwrap()];
        assert!(!run(&guarded, &mv), "rename of the state dir must fail");
        let cat = state.join("service.json");
        assert!(!run(&guarded, &["/bin/cat", cat.to_str().unwrap()]));
        assert!(run("(version 1)(allow default)", &mv), "control");
    }

    /// Kernel check (#718): a plain `opencode.json` in an ancestor of the
    /// launch dir is readable; a symlink, hard link or directory there is
    /// refused by name, so it never reaches the file it points at.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin/sandbox-exec, /bin/cat
    fn ancestor_opencode_json_is_readable_only_as_a_plain_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (a, b, c) = (root.join("a"), root.join("a/b"), root.join("a/b/c"));
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(a.join("opencode.json"), "PLAIN").unwrap();
        std::fs::write(root.join("secret"), "SECRET").unwrap();
        let svc = [root.join("x/service.json")];
        let refused = |f: PathBuf| {
            let err = profile_tail(&root, &c, &svc, 1).unwrap_err();
            assert!(err.contains(&f.display().to_string()), "{err}");
            std::fs::remove_file(&f)
                .or_else(|_| std::fs::remove_dir(&f))
                .unwrap();
        };
        std::os::unix::fs::symlink(root.join("secret"), b.join("opencode.json")).unwrap();
        refused(b.join("opencode.json"));
        std::fs::hard_link(root.join("secret"), c.join("opencode.jsonc")).unwrap();
        refused(c.join("opencode.jsonc"));
        std::fs::create_dir(b.join("opencode.json")).unwrap();
        refused(b.join("opencode.json"));
        let tail = profile_tail(&root, &c, &svc, 1).unwrap();
        let profile = format!(
            "(version 1)(allow default)(deny file-read-data (subpath \"{}\")){tail}",
            root.display()
        );
        let cat = |p: &Path| {
            let o = std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &profile, "/bin/cat"])
                .arg(p)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        assert_eq!(cat(&a.join("opencode.json")), "PLAIN");
        assert_eq!(cat(&root.join("secret")), "", "control: the deny holds");
    }

    #[test]
    fn prepare_writes_a_private_service_config() {
        let tmp = tempfile::tempdir().unwrap();
        let s = temp_env::with_vars(
            [("XDG_CONFIG_HOME", None::<&str>), ("XDG_STATE_HOME", None)],
            || prepare(tmp.path(), tmp.path(), &tmp.path().join("src/repo")).unwrap(),
        );
        let file = tmp.path().join("opencode-v2/config/opencode/service.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        let port = v["port"].as_u64().unwrap();
        assert_eq!(v["password"].as_str().unwrap().len(), 32);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let env: std::collections::HashMap<_, _> = s.env.into_iter().collect();
        assert!(env["XDG_STATE_HOME"].ends_with("opencode-v2/state"));
        assert_eq!(env["OPENCODE_DISABLE_MODELS_FETCH"], "1");
        assert!(
            s.sbpl
                .contains(&format!("(remote ip \"localhost:{port}\")"))
        );
        assert!(!s.sbpl.contains("49374"));
        let home = tmp.path().display();
        assert!(s.sbpl.contains(&format!(
            "(literal \"{home}/.config/opencode/service.json\")"
        )));
        assert!(
            s.sbpl
                .contains(&format!("{home}/.local/state/opencode/service.json"))
        );
        for read in [format!("{home}/.claude"), format!("{home}/src"), "/".into()] {
            assert!(s.sbpl.contains(&format!("(literal \"{read}\")")), "{read}");
        }
    }
}
