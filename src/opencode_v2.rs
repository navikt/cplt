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
    /// File grants placed before the profile's deny rules, so a deny
    /// (credential, `deny.paths`, `.env`) on the same file still wins.
    pub sbpl_before_denies: String,
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
    let (sbpl_before_denies, sbpl) = profile_tail(home, launch_dir, &files, port)?;
    Ok(Session {
        env,
        sbpl,
        sbpl_before_denies,
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

/// The SBPL rules a v2 session adds: (file grants that go before the
/// profile's denies, the tail).
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
) -> Result<(String, String), String> {
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
    let mut files = Vec::new();
    // v2 walks `AGENTS.md` from the launch dir up to `$HOME`, or up to the
    // project root when the launch dir is outside `$HOME` (instruction.ts).
    let stop = if launch_dir.starts_with(home) {
        home.to_path_buf()
    } else {
        let git = launch_dir.ancestors().find(|d| d.join(".git").exists());
        git.unwrap_or(launch_dir).to_path_buf()
    };
    for dir in home.ancestors().chain(launch_dir.ancestors()) {
        reads.push(dir.to_path_buf());
        for name in [".claude", ".agents", ".opencode"] {
            let entry = dir.join(name);
            if let Ok(real) = std::fs::canonicalize(&entry) {
                reads.push(real);
            }
            reads.push(entry);
        }
        // Discovery also resolves and reads each `opencode.json(c)` as config
        // (#718), and the instruction loader blocks the session when an
        // `AGENTS.md` it finds cannot be read. The launch dir is the project,
        // already readable: nothing to grant there.
        if dir == launch_dir {
            continue;
        }
        let agents = launch_dir.starts_with(dir) && dir.starts_with(&stop);
        for name in ["opencode.json", "opencode.jsonc", "AGENTS.md"] {
            if name != "AGENTS.md" || agents {
                grant_file(home, &dir.join(name), &mut files)?;
            }
        }
    }
    reads.sort();
    reads.dedup();
    files.sort();
    files.dedup();
    for p in reads.iter().chain(&files).chain(&denied).chain(&pinned) {
        crate::sandbox::validate_sbpl_path(p)?;
    }
    let lit = |ps: &[PathBuf]| {
        ps.iter()
            .map(|p| format!(" (literal \"{}\")", p.display()))
            .collect::<String>()
    };
    // `file-read*`, not `file-read-data`: Seatbelt lets an allow on the
    // narrower operation beat a later `file-read*` deny, whatever the order.
    let before = if files.is_empty() {
        String::new()
    } else {
        format!(
            ";; OpenCode v2 config and instruction files\n(allow file-read*{})\n",
            lit(&files)
        )
    };
    let tail = format!(
        "\n;; OpenCode v2 session service (#710)\n\
         (allow file-read-data{})\n\
         (deny file-read* file-write*{})\n\
         (deny file-write-unlink{})\n\
         (allow network-outbound (remote ip \"localhost:{port}\"))\n",
        lit(&reads),
        lit(&denied),
        lit(&pinned),
    );
    Ok((before, tail))
}

/// Host-side notes for a v2 launch, read by cplt and never passed into the
/// sandbox:
///
/// - a live host service shares `opencode.db` and resumes unfinished turns it
///   finds there, so it can carry on this session's work outside the sandbox;
/// - a fresh database skips the legacy `auth.json` import, so a user with v1
///   credentials starts logged out.
pub fn host_warnings(home: &Path) -> Vec<String> {
    let state = xdg_base("XDG_STATE_HOME", home, ".local/state");
    let data = xdg_base("XDG_DATA_HOME", home, ".local/share").join("opencode");
    let mut out = Vec::new();
    if let Some(pid) = host_service_pid(&state.join("opencode/service.json")) {
        out.push(format!(
            "A host OpenCode service (pid {pid}) is running and shares opencode.db with \
             this session. It may continue this session's unfinished turns outside the \
             sandbox. Stop it (`opencode service stop`) to keep all work inside cplt."
        ));
    }
    if logged_out_after_upgrade(&data, &home.join(crate::sandbox::CPLT_STATE_DIR)) {
        out.push(
            "OpenCode v2 did not import your v1 credentials (auth.json). Run \
             `opencode auth login`, or `opencode auth import` with an exported file."
                .into(),
        );
    }
    out
}

/// The pid in a service registration, if that process is alive.
fn host_service_pid(registration: &Path) -> Option<i32> {
    // Agent-writable dir: a planted FIFO or symlink must not hang or leak.
    let body = crate::agent::read_small_regular_file(registration)?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let pid = i32::try_from(v.get("pid")?.as_i64()?)
        .ok()
        .filter(|p| *p > 0)?;
    // SAFETY: signal 0 only checks that the pid exists.
    let alive = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    alive.then_some(pid)
}

/// `auth.json` holds entries but the database has no credential row. Reads
/// only the size of `auth.json` and a row count. After one count a marker
/// in cplt's state dir skips the check, so steady-state launch spawns nothing.
fn logged_out_after_upgrade(data: &Path, cplt_state: &Path) -> bool {
    let marker = cplt_state.join("opencode-v2-credentials-seen");
    if marker.exists() || std::fs::metadata(data.join("auth.json")).map_or(true, |m| m.len() <= 2) {
        return false;
    }
    let db = data.join("opencode.db");
    if !db.exists() {
        return true;
    }
    // No sqlite3, not a plain file, or a schema we do not know: stay quiet.
    let Some(rows) = sqlite_count(&db, "credential") else {
        return false;
    };
    // Any answer settles it: hint once at most, then never spawn again.
    let _ = std::fs::create_dir_all(cplt_state);
    let _ = std::fs::write(marker, "");
    rows == 0
}

/// `SELECT count(*) FROM <table>` on an OpenCode database, read-only. The
/// data dir is agent-writable, so only a plain file is opened: a planted FIFO
/// would hang sqlite3, and this runs before the sandbox starts.
fn sqlite_count(db: &Path, table: &str) -> Option<u64> {
    if !std::fs::symlink_metadata(db).ok()?.is_file() {
        return None;
    }
    let sqlite = crate::git::trusted_binary("sqlite3")?;
    #[allow(clippy::disallowed_methods)] // resolved above, not a PATH lookup
    let o = std::process::Command::new(sqlite)
        .args(["-readonly", "-batch", "-init", "/dev/null"])
        .arg(db)
        .arg(format!("SELECT count(*) FROM {table}"))
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    String::from_utf8_lossy(&o.stdout).trim().parse().ok()
}

/// The database exists and its schema bootstrap has committed. The file is
/// created before the migrations run, so existence alone is not enough.
fn bootstrapped(db: &Path) -> bool {
    sqlite_count(db, "migration").is_some_and(|n| n > 0)
}

/// On a first run (no `opencode.db` yet) two services that bootstrap the
/// database at once can fail with "database is locked": upstream locks the
/// bootstrap per process only. First launches take a host-side lock in cplt's
/// state dir; a background thread holds it until the bootstrap has committed,
/// or `limit`. A waiter never blocks longer than `limit`, and the lock goes
/// with the process if cplt exits sooner. Returns a warning when the lock
/// cannot be used at all; the launch then goes ahead ungated.
pub fn first_run_gate(home: &Path) -> Option<String> {
    let db = xdg_base("XDG_DATA_HOME", home, ".local/share").join("opencode/opencode.db");
    let lock = home
        .join(crate::sandbox::CPLT_STATE_DIR)
        .join("opencode-v2-first-run.lock");
    gate(db, &lock, std::time::Duration::from_secs(15), bootstrapped)
}

fn gate(
    db: PathBuf,
    lock: &Path,
    limit: std::time::Duration,
    ready: fn(&Path) -> bool,
) -> Option<String> {
    const TICK: std::time::Duration = std::time::Duration::from_millis(100);
    if db.exists() {
        return None;
    }
    let warn = |e: &dyn std::fmt::Display| {
        Some(format!(
            "Cannot serialize OpenCode's first start ({}: {e}); two sessions started \
             at once may fail with \"database is locked\".",
            lock.display()
        ))
    };
    let file = lock
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::File::create(lock));
    let file = match file {
        Ok(f) => f,
        Err(e) => return warn(&e),
    };
    let start = std::time::Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < limit => {
                std::thread::sleep(TICK);
            }
            Err(std::fs::TryLockError::WouldBlock) => return None,
            Err(std::fs::TryLockError::Error(e)) => return warn(&e),
        }
    }
    if ready(&db) {
        return None; // an earlier launch finished it while we waited
    }
    std::thread::spawn(move || {
        while !ready(&db) && start.elapsed() < limit {
            std::thread::sleep(TICK);
        }
        drop(file);
    });
    None
}

/// Grants `file` as a literal if it is a plain file with one link, or a
/// symlink (dotfile managers) whose launch-time target is one. The spelled
/// and the resolved path are granted, never a subpath, so repointing the link
/// later exposes nothing. A hard link, directory, FIFO, dangling link or a
/// target the sandbox denies is refused by name rather than left to fail as
/// EPERM. The grant itself goes before the profile's denies, so a deny this
/// check misses (`deny.paths`, `.env`) still wins in the kernel.
fn grant_file(home: &Path, file: &Path, reads: &mut Vec<PathBuf>) -> Result<(), String> {
    if std::fs::symlink_metadata(file).is_err() {
        return Ok(());
    }
    let fail = |why: String| {
        Err(format!(
            "{why}. OpenCode v2 reads {} at startup and stops when it cannot. \
             Replace it with a regular file or move it.",
            file.display()
        ))
    };
    let Ok(real) = std::fs::canonicalize(file) else {
        return fail(format!("{} is a dangling symlink", file.display()));
    };
    let shown = if real == file {
        file.display().to_string()
    } else {
        format!("{} points to {}, which", file.display(), real.display())
    };
    if !std::fs::symlink_metadata(&real).is_ok_and(|m| m.is_file() && m.nlink() == 1) {
        return fail(format!("{shown} is not a regular file with one link"));
    }
    if crate::sandbox::first_party_read_target(home, file).as_ref() != Some(&real) {
        return fail(format!("{shown} is a file the sandbox denies"));
    }
    reads.extend([real, file.to_path_buf()]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_service_pid_needs_a_live_process() {
        let tmp = tempfile::tempdir().unwrap();
        let reg = tmp.path().join("service.json");
        let me = std::process::id();
        std::fs::write(&reg, format!("{{\"pid\":{me},\"password\":\"x\"}}")).unwrap();
        assert_eq!(host_service_pid(&reg), Some(me as i32));
        // A reaped child's pid is free.
        #[allow(clippy::disallowed_methods)] // test: any short-lived process
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let dead = child.id();
        child.wait().unwrap();
        std::fs::write(&reg, format!("{{\"pid\":{dead}}}")).unwrap();
        assert_eq!(host_service_pid(&reg), None);
        std::fs::write(&reg, "{}").unwrap();
        assert_eq!(host_service_pid(&reg), None);
        // A planted FIFO must not hang the launch.
        std::fs::remove_file(&reg).unwrap();
        let c = std::ffi::CString::new(reg.to_str().unwrap()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(host_service_pid(&reg), None);
    }

    #[test]
    fn logged_out_after_upgrade_reads_the_credential_count() {
        let tmp = tempfile::tempdir().unwrap();
        let (data, st) = (tmp.path().join("data"), tmp.path().join("st"));
        std::fs::create_dir_all(&data).unwrap();
        assert!(!logged_out_after_upgrade(&data, &st), "no auth.json");
        std::fs::write(data.join("auth.json"), "{}").unwrap();
        assert!(!logged_out_after_upgrade(&data, &st), "empty auth.json");
        std::fs::write(data.join("auth.json"), "{\"a\":{}}").unwrap();
        assert!(logged_out_after_upgrade(&data, &st), "no database yet");
        let db = data.join("opencode.db");
        #[allow(clippy::disallowed_methods)] // resolved, not a PATH lookup
        let sql = |q: &str| {
            crate::git::trusted_binary("sqlite3")
                .map(std::process::Command::new)
                .and_then(|mut c| c.arg(&db).arg(q).status().ok())
                .is_some_and(|s| s.success())
        };
        if !sql("CREATE TABLE credential (id TEXT)") {
            return; // no sqlite3 on this host
        }
        assert!(logged_out_after_upgrade(&data, &st), "no credential rows");
        let marker = st.join("opencode-v2-credentials-seen");
        assert!(marker.exists(), "hint once, then skip");
        assert!(!logged_out_after_upgrade(&data, &st), "marker skips");
        std::fs::remove_file(&marker).unwrap();
        assert!(sql("INSERT INTO credential VALUES ('c')"));
        assert!(!logged_out_after_upgrade(&data, &st));
        assert!(marker.exists());
    }

    #[test]
    fn sqlite_count_refuses_a_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("opencode.db");
        let c = std::ffi::CString::new(db.to_str().unwrap()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t = std::time::Instant::now();
        assert_eq!(sqlite_count(&db, "credential"), None);
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
    }

    /// Test stand-in for the migration check: a non-empty file is "done".
    fn non_empty(db: &Path) -> bool {
        std::fs::metadata(db).is_ok_and(|m| m.len() > 0)
    }

    #[test]
    fn first_run_gate_serializes_until_the_bootstrap_is_done() {
        use std::time::{Duration, Instant};
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("opencode.db");
        let lock = tmp.path().join("st/first-run.lock");
        let limit = Duration::from_secs(10);
        assert_eq!(gate(db.clone(), &lock, limit, non_empty), None);
        let t = Instant::now();
        let maker = {
            let db = db.clone();
            std::thread::spawn(move || {
                // The file appears before the bootstrap commits.
                std::thread::sleep(Duration::from_millis(200));
                std::fs::write(&db, "").unwrap();
                std::thread::sleep(Duration::from_millis(600));
                std::fs::write(&db, "x").unwrap();
            })
        };
        // A second first-run launch, started before the file exists.
        assert_eq!(gate(db.clone(), &lock, limit, non_empty), None);
        let waited = t.elapsed();
        maker.join().unwrap();
        assert!(waited >= Duration::from_millis(700), "{waited:?}");
        assert!(waited < limit, "{waited:?}");
        let t = Instant::now();
        assert_eq!(gate(db, &lock, limit, non_empty), None);
        assert!(t.elapsed() < Duration::from_millis(50), "database exists");
    }

    #[test]
    fn first_run_gate_warns_when_the_lock_is_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("lockdir");
        std::fs::create_dir(&lock).unwrap(); // File::create on a dir fails
        let w = gate(
            tmp.path().join("opencode.db"),
            &lock,
            std::time::Duration::from_secs(1),
            non_empty,
        );
        assert!(w.is_some_and(|w| w.contains("database is locked")));
    }

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
        let tail = profile_tail(&root, &root, &[root.join("cfg/opencode/service.json")], 1)
            .unwrap()
            .1;
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
        let tail = profile_tail(&root, &root, &[state.join("service.json")], 1)
            .unwrap()
            .1;
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

    /// Kernel check (#718): a plain `opencode.json` or `AGENTS.md` in an
    /// ancestor of the launch dir is readable, and so is a symlink to a plain
    /// file (at both names); a hard link, directory, FIFO or dangling link
    /// there is refused by name.
    #[cfg(target_os = "macos")]
    #[test]
    #[allow(clippy::disallowed_methods)] // fixed /usr/bin/sandbox-exec, /bin/cat
    fn ancestor_opencode_json_is_readable_only_as_a_plain_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (a, b, c) = (root.join("a"), root.join("a/b"), root.join("a/b/c"));
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(a.join("opencode.json"), "PLAIN").unwrap();
        std::fs::write(a.join("AGENTS.md"), "AGENTS").unwrap();
        std::fs::write(root.join("secret"), "SECRET").unwrap();
        std::fs::write(root.join("dot"), "DOT").unwrap();
        std::os::unix::fs::symlink(root.join("dot"), b.join("AGENTS.md")).unwrap();
        let svc = [root.join("x/service.json")];
        let refused = |f: PathBuf| {
            let err = profile_tail(&root, &c, &svc, 1).unwrap_err();
            assert!(err.contains(&f.display().to_string()), "{err}");
            std::fs::remove_file(&f)
                .or_else(|_| std::fs::remove_dir(&f))
                .unwrap();
        };
        std::os::unix::fs::symlink(root.join("gone"), b.join("opencode.json")).unwrap();
        refused(b.join("opencode.json"));
        assert!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(root.join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        std::os::unix::fs::symlink(root.join("fifo"), b.join("opencode.json")).unwrap();
        refused(b.join("opencode.json"));
        std::fs::hard_link(root.join("secret"), b.join("opencode.jsonc")).unwrap();
        refused(b.join("opencode.jsonc"));
        std::fs::create_dir(b.join("opencode.json")).unwrap();
        refused(b.join("opencode.json"));
        // In the launch dir (the project, already readable) a link is fine.
        std::os::unix::fs::symlink(root.join("secret"), c.join("opencode.json")).unwrap();
        let (before, tail) = profile_tail(&root, &c, &svc, 1).unwrap();
        assert!(!before.contains("c/opencode.json"), "{before}");
        let deny_root = format!("(deny file-read* (subpath \"{}\"))", root.display());
        let cat_with = |profile: &str, p: &Path| {
            let o = std::process::Command::new("/usr/bin/sandbox-exec")
                .args(["-p", profile, "/bin/cat"])
                .arg(p)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        let profile = format!("(version 1)(allow default){deny_root}{before}{tail}");
        let cat = |p: &Path| cat_with(&profile, p);
        assert_eq!(cat(&a.join("opencode.json")), "PLAIN");
        assert_eq!(cat(&a.join("AGENTS.md")), "AGENTS");
        assert_eq!(cat(&b.join("AGENTS.md")), "DOT", "symlink to a plain file");
        assert_eq!(cat(&root.join("secret")), "", "control: the deny holds");
        // A deny after the grants (the profile's deny section) still wins.
        let later = format!(
            "(version 1)(allow default){before}(deny file-read* (subpath \"{}\")){tail}",
            root.join("dot").display()
        );
        assert_eq!(cat_with(&later, &b.join("AGENTS.md")), "");
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
