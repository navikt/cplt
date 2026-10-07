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
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// What the launch adds for a v2 session.
pub struct Session {
    pub port: u16,
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
    let config = scratch.join("opencode-v2/config");
    let state = scratch.join("opencode-v2/state");
    std::fs::create_dir_all(&state).map_err(|e| format!("{}: {e}", state.display()))?;
    build_overlay(&config_base, &config).map_err(|e| format!("{}: {e}", config.display()))?;
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
        ("OPENCODE_DISABLE_MODELS_FETCH".into(), "1".into()),
        ("OPENCODE_DISABLE_AUTOUPDATE".into(), "1".into()),
    ];
    Ok(Session {
        port,
        env,
        sbpl: profile_tail(home, launch_dir, &[config_base, state_base], port)?,
    })
}

/// `overlay` = a link per entry of `user`, except `opencode`, which becomes a
/// real dir holding a link per entry of `user/opencode` except `service.json`.
fn build_overlay(user: &Path, overlay: &Path) -> std::io::Result<()> {
    let own = overlay.join("opencode");
    std::fs::create_dir_all(&own)?;
    for (from, to, skip) in [
        (user, overlay, "opencode"),
        (&user.join("opencode"), &own, "service.json"),
    ] {
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

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// The SBPL rules a v2 session adds.
///
/// v2's config discovery resolves `$HOME` and every parent of the working dir,
/// plus the `.claude` and `.agents` entries in each, and treats any error
/// other than "not found" as fatal. Those dir entries themselves become
/// readable (a listing of names); their contents stay denied. Both host
/// `service.json` files are denied at the spelled and the resolved path.
fn profile_tail(
    home: &Path,
    launch_dir: &Path,
    bases: &[PathBuf],
    port: u16,
) -> Result<String, String> {
    let mut denied = Vec::new();
    for base in bases {
        let file = base.join("opencode/service.json");
        let real = std::fs::canonicalize(base)
            .map_or_else(|_| file.clone(), |b| b.join("opencode/service.json"));
        denied.push(file);
        denied.push(real);
    }
    denied.dedup();
    let mut reads = Vec::new();
    for dir in home.ancestors().chain(launch_dir.ancestors()) {
        reads.extend([dir.to_path_buf(), dir.join(".claude"), dir.join(".agents")]);
    }
    reads.sort();
    reads.dedup();
    for p in reads.iter().chain(&denied) {
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
         (allow network-outbound (remote ip \"localhost:{port}\"))\n",
        lit(&reads),
        lit(&denied),
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
        build_overlay(&user, &ov).unwrap();
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
        build_overlay(&tmp.path().join("missing"), &tmp.path().join("ov2")).unwrap();
        assert!(tmp.path().join("ov2/opencode").is_dir());
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
        assert_eq!(v["port"], s.port);
        assert_eq!(v["password"].as_str().unwrap().len(), 32);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        let env: std::collections::HashMap<_, _> = s.env.into_iter().collect();
        assert!(env["XDG_STATE_HOME"].ends_with("opencode-v2/state"));
        assert_eq!(env["OPENCODE_DISABLE_MODELS_FETCH"], "1");
        assert!(
            s.sbpl
                .contains(&format!("(remote ip \"localhost:{}\")", s.port))
        );
        assert!(!s.sbpl.contains("49374"));
        let home = tmp.path().display();
        assert!(s.sbpl.contains(&format!(
            "(deny file-read* file-write* (literal \"{home}/.config/opencode/service.json\")"
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
