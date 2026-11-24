//! Opt-in session summary for launchers (#1157).
//!
//! A launcher such as nav-pilot sets `CPLT_SESSION_SUMMARY=<path>`, and on exit
//! the parent writes one JSON object there. cplt sends nothing anywhere; the
//! launcher decides what, if anything, to do with the file.
//!
//! Privacy contract (owner-approved field list in #1157): no session id, no
//! timestamps, no paths, no repository names, no argv, no env values. Hostnames
//! appear only for suffixes the launcher names in `CPLT_SESSION_SUMMARY_HOSTS`.
//! The schema is add-only: readers ignore unknown fields.
//!
//! The path is written by the unsandboxed parent, so it is treated like any
//! other file the agent could have planted: it must not lie inside a write
//! grant, and a symlink or non-file at the path is refused rather than replaced.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

pub const ENV: &str = "CPLT_SESSION_SUMMARY";
pub const HOSTS_ENV: &str = "CPLT_SESSION_SUMMARY_HOSTS";
/// Both variables are parent-only: `build_sandbox_env` strips them even past
/// `--pass-env` and `--inherit-env`.
pub const PARENT_ONLY_ENV: &[&str] = &[ENV, HOSTS_ENV];

/// Bound on distinct blocked hosts kept for the suffix filter.
const MAX_BLOCKED_HOSTS: usize = 512;

/// Every stable message id cplt can report in `hints_shown` /
/// `warnings_shown`, with what it means. Add-only: an id is never renamed or
/// reused. Documented in docs/session-summary.md.
pub const MESSAGE_IDS: &[(&str, &str)] = &[
    (
        "hint.push-gh-guard",
        "HTTPS push to GitHub has no credential helper while the gh guard is off",
    ),
    (
        "hint.otlp-vendor-auth",
        "OTLP vendor auth header is redacted from the sandbox",
    ),
    (
        "hint.untrusted-repo-config",
        "the repository's .cplt.toml has proposals nobody approved",
    ),
    (
        "hint.opencode-v2-auth-content",
        "OPENCODE_AUTH_CONTENT handling for OpenCode v2",
    ),
    (
        "warn.doctor-flag-deprecated",
        "--doctor is deprecated in favour of `cplt doctor`",
    ),
    ("warn.opencode-v2-host", "OpenCode v2 host setup warning"),
    ("warn.opencode-v2-first-run", "OpenCode v2 first-run gate"),
    (
        "warn.agent-binary-writable",
        "the agent binary sits in a tree the sandbox makes writable",
    ),
    (
        "warn.claude-brief",
        "the Claude Code brief could not be written",
    ),
    (
        "warn.managed-guard",
        "managed config guard reported a finding at exit",
    ),
    (
        "warn.managed-unsettled",
        "the managed-config check could not settle at exit",
    ),
    (
        "warn.copilot-trusted-folder",
        "the session added a Copilot trustedFolders entry",
    ),
    (
        "warn.bubblewrap-unavailable",
        "bubblewrap unavailable, Landlock + seccomp only",
    ),
    (
        "warn.session-summary-path-refused",
        "CPLT_SESSION_SUMMARY path refused",
    ),
    (
        "warn.session-summary-hosts-malformed",
        "CPLT_SESSION_SUMMARY_HOSTS had malformed entries",
    ),
    ("warn.unclassified", "a warning that has no stable id yet"),
];

/// The id a warning without its own id is reported under.
pub const UNCLASSIFIED: &str = "warn.unclassified";

#[derive(Default)]
struct State {
    /// The launch path was entered; only then is a summary written.
    launched: bool,
    path: Option<PathBuf>,
    agent: Option<String>,
    backend: Option<&'static str>,
    startup_ms: Option<u64>,
    exit_code: Option<u8>,
    exit_reason: Option<&'static str>,
    signal: Option<i32>,
    /// The audit's "Session ended (exit N)" line already said the code.
    exit_reported: bool,
    net: BTreeMap<&'static str, u64>,
    blocked_hosts: BTreeSet<String>,
    messages: Vec<&'static str>,
    settings: Vec<String>,
    managed_layer_used: bool,
    repo_config: Option<&'static str>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(State::default))
}

/// Call first thing in `main`: `duration_s` and `startup_ms` count from here.
pub fn mark_process_start() {
    START.get_or_init(Instant::now);
}

fn since_start() -> std::time::Duration {
    START.get_or_init(Instant::now).elapsed()
}

/// The launch path was entered with `path` from the environment.
/// No path yet: [`set_path`] stores one only after [`path_refusal`] cleared it,
/// so a launch that fails before the check writes nothing.
pub fn begin(agent: &str) {
    with(|s| {
        s.launched = true;
        s.agent = Some(agent.to_string());
    });
}

/// Store the path [`path_refusal`] returned.
pub fn set_path(path: PathBuf) {
    with(|s| s.path = Some(path));
}

/// The path from [`ENV`], if set and non-empty. Read only by the parent.
pub fn path_from_env() -> Option<PathBuf> {
    std::env::var_os(ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Drop the path (it was refused). Nothing is written afterwards.
pub fn launched() -> bool {
    with(|s| s.launched)
}

pub fn set_backend(backend: &'static str) {
    with(|s| s.backend = Some(backend));
}

pub fn set_settings(names: Vec<String>) {
    with(|s| s.settings = names);
}

pub fn set_managed_layer_used(used: bool) {
    with(|s| s.managed_layer_used = used);
}

/// `none` / `untrusted` / `trusted` / `changed`. The first call wins, so the
/// trust check can say `changed` before the launch path knows the rest.
pub fn set_repo_config(state: &'static str) {
    with(|s| {
        s.repo_config.get_or_insert(state);
    });
}

/// The agent is about to be spawned.
pub fn mark_started() {
    let ms = since_start().as_millis() as u64;
    with(|s| {
        s.startup_ms.get_or_insert(ms);
    });
}

/// The post-session report printed the exit code itself.
pub fn mark_exit_reported() {
    with(|s| s.exit_reported = true);
}

/// The child was killed by `signal` (recorded by the wait loop).
pub fn set_signal(signal: i32) {
    with(|s| s.signal = Some(signal));
}

/// The session ended with `code`.
pub fn finish(code: u8) {
    with(|s| {
        s.exit_code = Some(code);
        s.exit_reason = Some(if s.signal.is_some() { "signal" } else { "exit" });
    });
}

/// The launch failed before the agent ran.
pub fn setup_failed() {
    with(|s| {
        if s.exit_reason.is_none() {
            s.exit_code = Some(1);
            s.exit_reason = Some("sandbox-setup-failed");
        }
    });
}

/// Record a message id. Ids outside [`MESSAGE_IDS`] are a bug, caught by
/// `every_used_id_is_in_the_table`; at runtime they fall back to unclassified.
pub fn record_message(id: &'static str) {
    let id = if MESSAGE_IDS.iter().any(|(known, _)| *known == id) {
        id
    } else {
        debug_assert!(false, "message id {id} is not in MESSAGE_IDS");
        UNCLASSIFIED
    };
    with(|s| s.messages.push(id));
}

/// Map a proxy log status to a `net_blocked` reason, or `None` when the
/// status is not a block or upstream failure.
pub fn net_reason(status: &str) -> Option<&'static str> {
    match status {
        "BLOCKED" => Some("blocklist"),
        "BLOCKED-ALLOWLIST" | "BLOCKED-PORT" => Some("not-allowed"),
        s if s.starts_with("BLOCKED-PRIVATE") => Some("private"),
        s if s.starts_with("CONNECT-FAIL:upstream") => Some("upstream-fail"),
        _ => None,
    }
}

/// Called by the proxy for every CONNECT verdict.
pub fn record_net(status: &str, host: &str) {
    let Some(reason) = net_reason(status) else {
        return;
    };
    with(|s| {
        *s.net.entry(reason).or_insert(0) += 1;
        if let Some(host) = dns_host(host)
            && reason != "upstream-fail"
            && s.blocked_hosts.len() < MAX_BLOCKED_HOSTS
        {
            s.blocked_hosts.insert(host);
        }
    });
}

/// The host normalised, if it is a DNS name (letters, digits, `-`, `.`, at
/// most 253 bytes). The host comes from the agent's CONNECT line.
fn dns_host(host: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
    .then_some(host)
}

/// Parse `CPLT_SESSION_SUMMARY_HOSTS`: comma-separated DNS suffixes. Returns
/// the normalized suffixes and how many entries were malformed and dropped.
pub fn parse_suffixes(raw: &str) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut bad = 0;
    for entry in raw.split(',') {
        let s = entry.trim().trim_matches('.').to_ascii_lowercase();
        if s.is_empty() {
            if !entry.trim().is_empty() {
                bad += 1;
            }
            continue;
        }
        let valid = s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if valid {
            out.push(s);
        } else {
            bad += 1;
        }
    }
    out.sort();
    out.dedup();
    (out, bad)
}

/// Exact suffix match on a label boundary: `nav.no` matches `nav.no` and
/// `x.nav.no`, never `evilnav.no`.
pub fn host_matches(host: &str, suffixes: &[String]) -> bool {
    suffixes.iter().any(|s| {
        host == s
            || host
                .strip_suffix(s.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Clear `path` for the summary, or say why not. Returns the path with its
/// parent canonicalised, which is what gets written at exit.
///
/// `on_path` is `check::writable_tree_on_path` against the emitted policy: it
/// walks every component and every symlink hop, so a link chain through a
/// write grant (`out/l1 -> proj/l2 -> victim`) is refused even though both
/// ends lie outside it. The parent must exist now; one that does not resolve
/// cannot be checked.
pub fn path_refusal(
    path: &Path,
    on_path: impl Fn(&Path) -> Option<(PathBuf, PathBuf)>,
) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("it is not an absolute path".into());
    }
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err("it names no file".into());
    };
    let canonical = std::fs::canonicalize(parent)
        .map_err(|e| format!("its directory cannot be resolved ({e})"))?
        .join(name);
    for candidate in [path, canonical.as_path()] {
        if let Some((entry, tree)) = on_path(candidate) {
            return Err(format!(
                "{} lies inside {}, which the sandbox can write",
                entry.display(),
                tree.display()
            ));
        }
    }
    Ok(canonical)
}

/// Render the summary. `suffixes` filters `net_blocked_hosts`.
fn render(s: &State, suffixes: &[String]) -> serde_json::Value {
    use serde_json::{Map, Value, json};
    let mut m = Map::new();
    m.insert("schema".into(), json!(1));
    m.insert("cplt_version".into(), json!(env!("CARGO_PKG_VERSION")));
    m.insert("agent".into(), json!(s.agent));
    let backend = s.backend.unwrap_or(if cfg!(target_os = "macos") {
        "seatbelt"
    } else {
        "landlock"
    });
    m.insert("backend".into(), json!(backend));
    m.insert("os".into(), json!(std::env::consts::OS));
    if let Some(ms) = s.startup_ms {
        m.insert("startup_ms".into(), json!(ms));
    }
    m.insert("duration_s".into(), json!(since_start().as_secs()));
    m.insert("exit_code".into(), json!(s.exit_code));
    m.insert("agent_exit_reason".into(), json!(s.exit_reason));
    let net: Map<String, Value> = ["blocklist", "not-allowed", "private", "upstream-fail"]
        .iter()
        .map(|r| ((*r).to_string(), json!(s.net.get(r).copied().unwrap_or(0))))
        .collect();
    m.insert("net_blocked".into(), Value::Object(net));
    let hosts: Vec<&String> = s
        .blocked_hosts
        .iter()
        .filter(|h| host_matches(h, suffixes))
        .collect();
    m.insert("net_blocked_hosts".into(), json!(hosts));
    let ids = |prefix: &str| -> Vec<&str> {
        let set: BTreeSet<&str> = s
            .messages
            .iter()
            .copied()
            .filter(|id| id.starts_with(prefix))
            .collect();
        set.into_iter().collect()
    };
    m.insert("hints_shown".into(), json!(ids("hint.")));
    m.insert("warnings_shown".into(), json!(ids("warn.")));
    m.insert("settings_in_effect".into(), json!(s.settings));
    m.insert("managed_layer_used".into(), json!(s.managed_layer_used));
    m.insert("repo_config".into(), json!(s.repo_config.unwrap_or("none")));
    Value::Object(m)
}

/// Write `contents` to `path` (parent already canonical, from
/// [`path_refusal`]). The parent is resolved again and must not have moved,
/// then opened `O_DIRECTORY | O_NOFOLLOW`; everything after is relative to
/// that fd: a fresh 0600 temp file (`O_EXCL | O_NOFOLLOW`) renamed over the
/// target. A symlink or anything but a regular file at `path` is refused.
pub fn write_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let refuse = |why: &str| std::io::Error::other(why.to_string());
    let dir = path.parent().ok_or_else(|| refuse("no parent dir"))?;
    let name = path.file_name().ok_or_else(|| refuse("no file name"))?;
    if std::fs::canonicalize(dir)? != dir {
        return Err(refuse("its directory changed since launch"));
    }
    let cstr = |b: &[u8]| CString::new(b).map_err(|_| refuse("NUL in path"));
    let dir_c = cstr(dir.as_os_str().as_bytes())?;
    let name_c = cstr(name.as_bytes())?;
    let tmp_c = cstr(format!(".{}.{}.tmp", name.to_string_lossy(), std::process::id()).as_bytes())?;
    // SAFETY: plain syscalls on NUL-terminated strings; fds are owned below.
    let dfd = unsafe {
        libc::open(
            dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let dfd = unsafe { OwnedFd::from_raw_fd(dfd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::fstatat(
            dfd.as_raw_fd(),
            name_c.as_ptr(),
            &raw mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r == 0 && (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(refuse("the path exists and is not a regular file"));
    }
    let fd = unsafe {
        libc::openat(
            dfd.as_raw_fd(),
            tmp_c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut f = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let result = f
        .write_all(contents)
        .and_then(|()| f.sync_all())
        .and_then(|()| {
            let r = unsafe {
                libc::renameat(
                    dfd.as_raw_fd(),
                    tmp_c.as_ptr(),
                    dfd.as_raw_fd(),
                    name_c.as_ptr(),
                )
            };
            if r == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    if result.is_err() {
        unsafe { libc::unlinkat(dfd.as_raw_fd(), tmp_c.as_ptr(), 0) };
    }
    result
}

/// Write the summary if the launch asked for one. Called once from `main`.
pub fn write_if_requested() {
    let (path, json) = {
        let guard = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(s) = guard.as_ref().filter(|s| s.launched) else {
            return;
        };
        let Some(path) = s.path.clone() else {
            return;
        };
        let raw = std::env::var(HOSTS_ENV).unwrap_or_default();
        let (suffixes, _) = parse_suffixes(&raw);
        (path, render(s, &suffixes))
    };
    let mut bytes = json.to_string().into_bytes();
    bytes.push(b'\n');
    if let Err(e) = write_file(&path, &bytes) {
        crate::ui::error(&format!("cannot write the session summary: {e}"));
    }
}

/// The one-line exit reason for a non-zero session, with the last hint shown.
/// `None` on exit 0 and on setup failure, whose error `main` already printed.
pub fn exit_line() -> Option<String> {
    with(|s| exit_line_for(s))
}

fn exit_line_for(s: &State) -> Option<String> {
    {
        if !s.launched {
            return None;
        }
        let what = match (s.exit_reason?, s.exit_code?, s.signal) {
            (_, 0, _) | ("sandbox-setup-failed", ..) => return None,
            ("signal", _, Some(sig)) => Some(format!("agent killed by signal {sig}")),
            // Already said by the audit's "Session ended (exit N)" line.
            _ if s.exit_reported => None,
            (_, code, _) => Some(format!("agent exited with code {code}")),
        };
        let hint = s.messages.iter().rev().find(|id| id.starts_with("hint."));
        match (what, hint) {
            (Some(what), Some(id)) => Some(format!("{what} (hint shown this session: {id})")),
            (None, Some(id)) => Some(format!("hint shown this session: {id}")),
            (what, None) => what,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State {
            launched: true,
            agent: Some("copilot".into()),
            ..State::default()
        }
    }

    #[test]
    fn ids_are_unique_and_prefixed() {
        let mut seen = BTreeSet::new();
        for (id, _) in MESSAGE_IDS {
            assert!(id.starts_with("hint.") || id.starts_with("warn."), "{id}");
            assert!(seen.insert(*id), "duplicate id {id}");
        }
    }

    /// Every `warn_id("…")` in the source names an id in the table, and the
    /// launch path (`fn run` in main.rs) prints no warning without an id.
    #[test]
    fn every_used_id_is_in_the_table() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![];
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        let mut used = 0;
        for f in files.iter().filter(|f| !f.ends_with("session_summary.rs")) {
            let text = std::fs::read_to_string(f).unwrap();
            for chunk in text.split("warn_id(").skip(1) {
                let Some(rest) = chunk.trim_start().strip_prefix('"') else {
                    continue;
                };
                let id = rest.split('"').next().unwrap();
                assert!(
                    MESSAGE_IDS.iter().any(|(k, _)| *k == id),
                    "{}: {id} is not in MESSAGE_IDS",
                    f.display()
                );
                used += 1;
            }
        }
        assert!(used >= 10, "found only {used} warn_id calls");
        let main =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
                .unwrap();
        let start = main.find("\nfn run(mut cli: Cli)").unwrap();
        let end = start + main[start..].find("\nfn main()").unwrap();
        assert!(
            !main[start..end].contains("ui::warn("),
            "the launch path prints a warning without a stable id: use ui::warn_id"
        );
    }

    #[test]
    fn shape_and_privacy() {
        let mut s = state();
        s.exit_code = Some(3);
        s.exit_reason = Some("exit");
        s.net.insert("blocklist", 2);
        s.blocked_hosts.insert("api.nav.no".into());
        s.blocked_hosts.insert("evil.example".into());
        s.blocked_hosts.insert("evilnav.no".into());
        s.messages = vec![
            "hint.push-gh-guard",
            "warn.managed-guard",
            "hint.push-gh-guard",
        ];
        let v = render(&s, &["nav.no".to_string()]);
        assert_eq!(v["schema"], 1);
        assert_eq!(v["exit_code"], 3);
        assert_eq!(v["agent_exit_reason"], "exit");
        assert_eq!(v["net_blocked"]["blocklist"], 2);
        assert_eq!(v["net_blocked"]["upstream-fail"], 0);
        assert_eq!(v["net_blocked_hosts"], serde_json::json!(["api.nav.no"]));
        assert_eq!(v["hints_shown"], serde_json::json!(["hint.push-gh-guard"]));
        assert_eq!(
            v["warnings_shown"],
            serde_json::json!(["warn.managed-guard"])
        );
        assert_eq!(v["repo_config"], "none");
        assert!(v.get("fs_denied").is_none() && v.get("exec_denied").is_none());
        assert!(v.get("session_id").is_none());
    }

    #[test]
    fn no_hosts_without_suffixes() {
        let mut s = state();
        s.blocked_hosts.insert("api.nav.no".into());
        assert_eq!(render(&s, &[])["net_blocked_hosts"], serde_json::json!([]));
    }

    #[test]
    fn suffix_parsing() {
        let (s, bad) = parse_suffixes(" Nav.NO., .nais.io,,a b,*,x..y,ok-1.dev");
        assert_eq!(s, vec!["nais.io", "nav.no", "ok-1.dev"]);
        assert_eq!(bad, 3);
        assert_eq!(parse_suffixes(""), (vec![], 0));
        assert!(host_matches("nav.no", &s));
        assert!(host_matches("a.b.nav.no", &s));
        assert!(!host_matches("evilnav.no", &s));
        assert!(!host_matches("nav.no.evil", &s));
    }

    #[test]
    fn net_reasons() {
        assert_eq!(net_reason("BLOCKED"), Some("blocklist"));
        assert_eq!(net_reason("BLOCKED-ALLOWLIST"), Some("not-allowed"));
        assert_eq!(net_reason("BLOCKED-PRIVATE-RESOLVED"), Some("private"));
        assert_eq!(
            net_reason("CONNECT-FAIL:upstream-dns"),
            Some("upstream-fail")
        );
        assert_eq!(net_reason("CONNECTED"), None);
        assert_eq!(net_reason("DNS-FAIL"), None);
    }

    fn canon_tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let c = std::fs::canonicalize(dir.path()).unwrap();
        (dir, c)
    }

    #[test]
    fn writes_0600_and_replaces() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, dir) = canon_tmp();
        let p = dir.join("s.json");
        std::fs::write(&p, "old").unwrap();
        write_file(&p, b"{}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{}");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn refuses_symlink_and_fifo() {
        let (_d, dir) = canon_tmp();
        let target = dir.join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_file(&link, b"{}").is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let fifo = dir.join("fifo.json");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(write_file(&fifo, b"{}").is_err());
    }

    /// A parent re-aimed after launch (a symlink swapped into the chain) is
    /// refused at write time, not followed.
    #[test]
    fn write_refuses_a_parent_that_moved() {
        let (_d, dir) = canon_tmp();
        let real = dir.join("real");
        let victim = dir.join("victim");
        std::fs::create_dir(&real).unwrap();
        std::fs::create_dir(&victim).unwrap();
        let checked = real.join("s.json");
        std::fs::remove_dir(&real).unwrap();
        std::os::unix::fs::symlink(&victim, &real).unwrap();
        assert!(write_file(&checked, b"{}").is_err());
        assert!(!victim.join("s.json").exists());
    }

    fn grant_policy(dir: &Path) -> crate::sandbox::LandlockPolicy {
        crate::sandbox::LandlockPolicy {
            fs_rules: vec![crate::sandbox::FsRule {
                nofollow: false,
                path: dir.to_path_buf(),
                access: crate::sandbox::FsAccess {
                    read: true,
                    write: true,
                    execute: false,
                    ioctl: false,
                    create_dirs: false,
                },
            }],
            net_rules: Vec::new(),
            bind_rules: Vec::new(),
            restrict_net_connect: true,
            restrict_net_bind: false,
            proxy_forced: false,
            home_dir: PathBuf::from("/home/u"),
            precreate_dirs: vec![],
            plain_file: None,
        }
    }

    #[test]
    fn path_inside_write_grant_is_refused() {
        let (_d, t) = canon_tmp();
        let (proj, out, victim) = (t.join("proj"), t.join("out"), t.join("victim"));
        for d in [&proj, &out, &victim] {
            std::fs::create_dir(d).unwrap();
        }
        let policy = grant_policy(&proj);
        let home = t.join("home");
        let ask = |p: &Path| {
            path_refusal(p, |q| {
                crate::check::writable_tree_on_path(&policy, &home, q)
            })
        };
        assert!(ask(&proj.join("s.json")).unwrap_err().contains("can write"));
        assert!(ask(Path::new("rel.json")).is_err());
        // Missing parent: cannot be checked, so refused.
        assert!(ask(&out.join("missing/s.json")).is_err());
        // Two hops: out/l1 -> proj/l2 -> victim. Both ends lie outside the
        // grant, but the agent can re-aim proj/l2.
        std::os::unix::fs::symlink(proj.join("l2"), out.join("l1")).unwrap();
        std::os::unix::fs::symlink(&victim, proj.join("l2")).unwrap();
        assert!(
            ask(&out.join("l1/s.json")).is_err(),
            "two-hop link through a grant"
        );
        assert_eq!(ask(&out.join("s.json")).unwrap(), out.join("s.json"));
    }

    #[test]
    fn stored_hosts_are_dns_names_only() {
        assert_eq!(dns_host("Evil.Example.").as_deref(), Some("evil.example"));
        assert_eq!(dns_host("a b\u{1b}[2K"), None);
        assert_eq!(dns_host(&"a".repeat(254)), None);
        assert_eq!(dns_host(""), None);
    }

    #[test]
    fn exit_line_quiet_on_zero_and_setup_failure() {
        let mut s = state();
        s.exit_code = Some(0);
        s.exit_reason = Some("exit");
        assert_eq!(exit_line_for(&s), None);
        s.exit_code = Some(1);
        s.exit_reason = Some("sandbox-setup-failed");
        assert_eq!(exit_line_for(&s), None);
        s.exit_reason = Some("exit");
        assert_eq!(exit_line_for(&s).unwrap(), "agent exited with code 1");
        s.exit_reported = true;
        assert_eq!(exit_line_for(&s), None);
        s.messages = vec!["hint.push-gh-guard"];
        assert_eq!(
            exit_line_for(&s).unwrap(),
            "hint shown this session: hint.push-gh-guard"
        );
        s.exit_code = Some(137);
        s.exit_reason = Some("signal");
        s.signal = Some(9);
        s.messages = vec!["hint.push-gh-guard", "warn.managed-guard"];
        assert_eq!(
            exit_line_for(&s).unwrap(),
            "agent killed by signal 9 (hint shown this session: hint.push-gh-guard)"
        );
    }
}
