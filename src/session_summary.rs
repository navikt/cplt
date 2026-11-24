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
pub fn begin(path: Option<PathBuf>, agent: &str) {
    with(|s| {
        s.launched = true;
        s.path = path;
        s.agent = Some(agent.to_string());
    });
}

/// The path from [`ENV`], if set and non-empty. Read only by the parent.
pub fn path_from_env() -> Option<PathBuf> {
    std::env::var_os(ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Drop the path (it was refused). Nothing is written afterwards.
pub fn disable() {
    with(|s| s.path = None);
}

pub fn enabled() -> bool {
    with(|s| s.launched && s.path.is_some())
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
        if reason != "upstream-fail" && s.blocked_hosts.len() < MAX_BLOCKED_HOSTS {
            s.blocked_hosts
                .insert(host.trim_end_matches('.').to_ascii_lowercase());
        }
    });
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

/// Why `path` must not be used, given the session's write grants.
///
/// `writable` answers whether a path lies inside a tree the sandbox can write
/// (`check::writable_tree_over` against the emitted policy). The parent dir is
/// also checked after resolving symlinks, so a link out of a grant into a
/// writable tree cannot launder it.
pub fn path_refusal(path: &Path, writable: impl Fn(&Path) -> Option<PathBuf>) -> Option<String> {
    if !path.is_absolute() {
        return Some("it is not an absolute path".into());
    }
    let Some(name) = path.file_name() else {
        return Some("it names no file".into());
    };
    let resolved = path
        .parent()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.join(name));
    for candidate in std::iter::once(path.to_path_buf()).chain(resolved) {
        if let Some(tree) = writable(&candidate) {
            return Some(format!(
                "it lies inside {}, which the sandbox can write",
                tree.display()
            ));
        }
    }
    None
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

/// Write `contents` to `path`: a fresh 0600 temp file in the same directory,
/// opened `O_EXCL | O_NOFOLLOW`, then renamed over the target. A symlink or
/// anything but a regular file at `path` is refused, never replaced.
pub fn write_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let refuse = |why: &str| std::io::Error::other(why.to_string());
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => {
            return Err(refuse("the path exists and is not a regular file"));
        }
        _ => {}
    }
    let dir = path.parent().ok_or_else(|| refuse("no parent dir"))?;
    let name = path.file_name().ok_or_else(|| refuse("no file name"))?;
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
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
            ("signal", _, Some(sig)) => format!("agent killed by signal {sig}"),
            (_, code, _) => format!("agent exited with code {code}"),
        };
        let hint = s.messages.iter().rev().find(|id| id.starts_with("hint."));
        Some(match hint {
            Some(id) => format!("{what} (hint shown this session: {id})"),
            None => what,
        })
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

    #[test]
    fn writes_0600_and_replaces() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.json");
        std::fs::write(&p, "old").unwrap();
        write_file(&p, b"{}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{}");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn refuses_symlink_and_fifo() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_file(&link, b"{}").is_err());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let fifo = dir.path().join("fifo.json");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(write_file(&fifo, b"{}").is_err());
    }

    #[test]
    fn path_inside_write_grant_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let grant = std::fs::canonicalize(dir.path()).unwrap();
        let writable = |p: &Path| p.starts_with(&grant).then(|| grant.clone());
        let inside = grant.join("s.json");
        assert!(
            path_refusal(&inside, writable)
                .unwrap()
                .contains("can write")
        );
        assert!(path_refusal(Path::new("rel.json"), writable).is_some());
        // A link from outside into the grant is resolved and refused.
        let outside = tempfile::tempdir().unwrap();
        let link = outside.path().join("l");
        std::os::unix::fs::symlink(&grant, &link).unwrap();
        assert!(path_refusal(&link.join("s.json"), writable).is_some());
        assert!(path_refusal(&outside.path().join("s.json"), writable).is_none());
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
