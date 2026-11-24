//! `open_url`: the broker opens an OAuth authorize URL in the host browser
//! for a sandboxed MCP client (owner decision 2026-11-17, #910).
//!
//! The sandbox side is a PATH shim named `open` (macOS) or `xdg-open`
//! (Linux), because OpenCode opens URLs through the npm `open` package, which
//! ignores `BROWSER`. On macOS the shim runs `cplt mcp-open-url <url>`, which
//! sends the URL to the broker; the broker checks it here and runs `open` with
//! the URL as one argv entry, never through a shell. Linux has no host opener:
//! `cplt mcp-open-url` checks the URL against `CPLT_OPEN_URL_HOSTS`, prints it
//! to stderr and `/dev/tty`, and exits 1 because nothing was opened.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::SOCKET_ENV;
use super::spec::Spec;
use crate::sandbox::{FsRule, LandlockPolicy};

/// First line a client sends for this op. Spec ids cannot contain `:`.
pub(crate) const OP_LINE: &str = "cplt:open_url";
/// An authorize URL with PKCE and state fits well inside this.
const MAX_LEN: usize = 4096;
/// The credential of a remote spec that runs OAuth (#1020).
const OAUTH_CREDENTIAL: &str = "oauth";

/// Opens per [`WINDOW`], and the window itself.
const MAX_OPENS: usize = 3;
const WINDOW: Duration = Duration::from_secs(60);

/// Hosts a URL may name: each oauth spec's `remote` URL host (the fleet
/// gateway), and only when that host is also one of the spec's `egressHosts`.
/// Other egress hosts stay out, so listing a login host there opens nothing.
/// No new config key: the spec already names where its OAuth flow goes.
/// The Entra login host is deliberately absent (owner decision 2026-11-17):
/// an authorize URL for a first-party client_id with a loopback redirect
/// would complete silently under browser SSO and hand the code to whoever
/// listens on that port. The gateway redirects the browser to Entra itself.
/// Empty means the op is off.
pub(crate) fn allowed_hosts<'a>(specs: impl Iterator<Item = &'a Spec>) -> Vec<String> {
    specs
        .filter(|s| s.credential.name == OAUTH_CREDENTIAL)
        .flat_map(|s| {
            s.egress_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .filter(|h| {
                    let one = [h.clone()];
                    s.remote.iter().any(|r| check(r, &one).is_ok())
                })
        })
        .collect()
}

/// At most [`MAX_OPENS`] opens per [`WINDOW`] and one opener at a time, so a
/// sandboxed client cannot flood tabs or pile up host processes.
#[derive(Default)]
pub(crate) struct Limiter {
    recent: Mutex<VecDeque<Instant>>,
    busy: Arc<AtomicBool>,
}

impl Limiter {
    /// Take a slot, or say why not. The returned flag is cleared when the
    /// opener exits.
    fn take(&self, now: Instant) -> Result<Arc<AtomicBool>, &'static str> {
        let mut recent = self.recent.lock().map_err(|_| "limiter poisoned")?;
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            recent.pop_front();
        }
        if recent.len() >= MAX_OPENS {
            return Err("rate limit: too many URLs opened this minute");
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            return Err("another URL is still being opened");
        }
        recent.push_back(now);
        Ok(Arc::clone(&self.busy))
    }
}

/// Strict check of `url`. Hand-parsed: no URL crate is a dependency, and a
/// parser that only accepts the narrow shape has less to get wrong.
pub(crate) fn check(url: &str, hosts: &[String]) -> Result<(), &'static str> {
    if url.len() > MAX_LEN {
        return Err("URL too long");
    }
    // Printable ASCII only: no control bytes, spaces or non-ASCII (IDN).
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("URL must be printable ASCII");
    }
    if url.contains('\\') {
        return Err("backslash in URL");
    }
    let rest = url.strip_prefix("https://").ok_or("URL must be https")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return Err("userinfo in URL");
    }
    if authority.contains('%') {
        return Err("percent-encoded host");
    }
    if authority.starts_with('[') {
        return Err("IP literal host");
    }
    let host = match authority.split_once(':') {
        None => authority,
        Some((h, "443")) => h,
        Some(_) => return Err("port other than 443"),
    };
    let host = host.to_ascii_lowercase();
    // An entry with a leading `.` is an `allow_private_domains` domain: the
    // proxy's own matcher (the domain and its subdomains, not siblings).
    let allowed = hosts.iter().any(|h| match h.strip_prefix('.') {
        Some(d) => crate::proxy::is_domain_match(&host, &[d.to_string()]),
        None => *h == host,
    });
    if allowed {
        Ok(())
    } else {
        Err(HOST_NOT_ALLOWED)
    }
}

const HOST_NOT_ALLOWED: &str = "host not allowed";

/// `proxy.allow_private_domains` as [`check`] entries (#1091). The session's
/// effective list, managed layer included, already normalised and stripped of
/// IP entries by config resolution.
#[must_use]
pub fn private_domain_entries(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .map(|d| crate::proxy::normalize_hostname(d))
        .filter(|d| !d.is_empty())
        .map(|d| format!(".{d}"))
        .collect()
}

/// The answer for a refused URL: for a host outside the list, name it and
/// the one-line fix.
fn refusal(url: &str, why: &str) -> String {
    match host_of(url).filter(|_| why == HOST_NOT_ALLOWED) {
        Some(h) => {
            format!(
                "denied: {h} is not allowed to open in the host browser. To allow it: cplt config set proxy.allow_private_domains {h}"
            )
        }
        None => format!("denied: {why}"),
    }
}

/// The lowercased host of a URL that passed [`check`]'s shape rules.
fn host_of(url: &str) -> Option<String> {
    url.strip_prefix("https://")
        .and_then(|r| r.split(['/', '?', '#']).next())
        .and_then(|a| a.split(':').next())
        .map(str::to_ascii_lowercase)
}

/// macOS only (owner decision 2026-11-17): LaunchServices picks the handler
/// from `~/Library/Preferences`, which the sandbox must not write. Linux has
/// no host opener: `xdg-open` resolves its handler through many agent-writable,
/// desktop-specific files (`~/.cache` ksycoca, `kdeglobals`, XFCE
/// `helpers.rc`), which would give host code execution. There the shim prints
/// the URL instead, see [`run`].
pub const HOST_OPENER: bool = cfg!(target_os = "macos");

/// The LaunchServices prefs dir when the session `policy` can write it, an
/// entry on the way to it, or anything a symlink under it leads through; the
/// launcher then turns the op off.
///
/// Each path is walked one component at a time by
/// [`crate::check::writable_tree_on_path`], so a two-hop chain
/// (`Preferences -> ~/dotfiles/prefs -> /elsewhere`) is caught at the
/// writable middle hop. A write grant inside the dir (or inside a symlinked
/// directory target under it) counts too. Fails closed if scanning `Preferences`
/// hits the entry or depth cap.
#[must_use]
pub fn opener_config_writable(policy: &LandlockPolicy, home: &Path) -> Option<PathBuf> {
    let prefs = home.join("Library/Preferences");
    // Grants given through a symlink match the resolved paths as well.
    let mut policy = policy.clone();
    let resolved: Vec<_> = policy
        .fs_rules
        .iter()
        .filter(|r| r.access.write)
        .map(|r| FsRule {
            path: real(&r.path),
            ..r.clone()
        })
        .collect();
    policy.fs_rules.extend(resolved);
    let mut paths = vec![prefs.clone()];
    let mut visited_dirs = HashSet::new();
    let truncated = collect_links(
        &prefs,
        4,
        MAX_COLLECT_ENTRIES,
        &mut paths,
        &mut visited_dirs,
    );
    let real_prefs = real(&prefs);
    let inside = policy.fs_rules.iter().any(|r| {
        r.access.write
            && (r.path.starts_with(&prefs)
                || r.path.starts_with(&real_prefs)
                || visited_dirs.iter().any(|d| r.path.starts_with(d)))
    });
    let on_path = paths
        .iter()
        .any(|p| crate::check::writable_tree_on_path(&policy, home, p).is_some());
    (truncated || inside || on_path).then_some(prefs)
}

/// The path with symlinks resolved as far as it exists.
fn real(p: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = p;
    loop {
        if let Ok(c) = cur.canonicalize() {
            return rest.iter().rev().fold(c, |a, n| a.join(n));
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                cur = parent;
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// Cap total directory entries scanned under `~/Library/Preferences` so a
/// symlink to a huge directory (such as `/`) cannot stall launch.
const MAX_COLLECT_ENTRIES: usize = 10_000;

/// Every symlink under `root` (and inside symlinked directories it points to),
/// to `depth` levels; the caller walks each chain. Records every visited
/// canonical directory in `visited` so cycles are skipped and write grants
/// inside symlinked directory targets are checked too. Returns `true` if
/// traversal was truncated by `max_entries` or `depth` (leaving an unvisited
/// directory or symlinked directory unchecked) so the caller can fail closed.
fn collect_links(
    root: &Path,
    depth: u8,
    max_entries: usize,
    out: &mut Vec<PathBuf>,
    visited: &mut HashSet<PathBuf>,
) -> bool {
    let mut queue = VecDeque::from([(root.to_path_buf(), depth)]);
    let mut seen_entries = 0usize;
    while let Some((dir, rem_depth)) = queue.pop_front() {
        let Ok(canon) = std::fs::canonicalize(&dir) else {
            continue;
        };
        if !visited.insert(canon.clone()) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&canon) else {
            continue;
        };
        for e in entries.flatten() {
            seen_entries += 1;
            if seen_entries > max_entries {
                return true;
            }
            let path = e.path();
            let Ok(ft) = e.file_type() else {
                continue;
            };
            let recurse = if ft.is_symlink() {
                out.push(path.clone());
                // `metadata` uses `stat` (never opens FIFOs/devices); only
                // recurse when the symlink resolves to a directory.
                std::fs::metadata(&path).is_ok_and(|m| m.is_dir())
            } else {
                ft.is_dir()
            };
            if recurse {
                if rem_depth == 0 {
                    // An already-visited directory (cycle) was already scanned;
                    // any unvisited directory leaves its subtree unchecked.
                    if std::fs::canonicalize(&path)
                        .ok()
                        .is_none_or(|c| !visited.contains(&c))
                    {
                        return true;
                    }
                } else {
                    queue.push_back((path, rem_depth - 1));
                }
            }
        }
    }
    false
}

/// The host opener: `/usr/bin/open` on macOS, none elsewhere.
fn opener(macos: bool) -> Option<PathBuf> {
    // Debug builds only, for the e2e suite: a fake opener from the parent's
    // own environment (the user's, never the agent's). Release ignores it.
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("CPLT_TEST_OPENER").filter(|_| macos) {
        return Some(p.into());
    }
    macos.then(|| "/usr/bin/open".into())
}

/// Host side: read the URL line, check it, open it. Answers `ok` or the reason.
pub(crate) fn serve(
    reader: &mut impl BufRead,
    reply: &mut impl Write,
    hosts: &[String],
    limiter: &Limiter,
    home: &Path,
    log: &super::Log,
) {
    let Some(url) = super::runtime::read_line(reader, MAX_LEN as u64 + 2) else {
        return;
    };
    let answer = match check(&url, hosts).and_then(|()| limiter.take(Instant::now())) {
        Err(why) => {
            let host = host_of(&url).unwrap_or_default();
            log.line("open_url", &format!("DENIED {host} {why}"));
            refusal(&url, why)
        }
        Ok(busy) => match opener(HOST_OPENER).map(|o| spawn_opener(&o, &url, home, busy)) {
            Some(Ok(())) => {
                // The host only: the query carries OAuth state and PKCE.
                let host = host_of(&url).unwrap_or_default();
                log.line("open_url", &format!("ALLOWED {host}"));
                "ok".to_string()
            }
            Some(Err(e)) => {
                limiter.busy.store(false, Ordering::Release);
                log.line("open_url", &format!("FAIL {e}"));
                "failed: cannot run the opener".to_string()
            }
            None => {
                limiter.busy.store(false, Ordering::Release);
                log.line("open_url", "FAIL no opener");
                "failed: no opener on the host".to_string()
            }
        },
    };
    let _ = writeln!(reply, "{answer}");
}

/// The opener's environment, like the broker's other host children
/// (`runtime::host_env`): cleared, then HOME, the trusted PATH, TMPDIR and
/// the locale.
fn opener_env(
    home: &Path,
    get: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(&'static str, std::ffi::OsString)> {
    let mut env = vec![
        ("HOME", home.as_os_str().to_owned()),
        ("PATH", crate::git::TRUSTED_BIN_DIRS.join(":").into()),
        ("TMPDIR", std::env::temp_dir().into_os_string()),
    ];
    let keep = ["LANG", "LC_ALL"];
    env.extend(keep.into_iter().filter_map(|k| get(k).map(|v| (k, v))));
    env
}

fn spawn_opener(
    opener: &Path,
    url: &str,
    home: &Path,
    busy: Arc<AtomicBool>,
) -> std::io::Result<()> {
    // `opener` is an absolute path from `opener()`, never a PATH lookup.
    #[allow(clippy::disallowed_methods)]
    let mut cmd = Command::new(opener);
    cmd.env_clear();
    for (k, v) in opener_env(home, &|k| std::env::var_os(k)) {
        cmd.env(k, v);
    }
    let mut child = cmd
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Reap it without holding the connection; the slot frees on exit.
    std::thread::spawn(move || {
        let _ = child.wait();
        busy.store(false, Ordering::Release);
    });
    Ok(())
}

/// `cplt mcp-open-url <url>`, inside the sandbox: ask the broker to open it.
pub fn run(url: &str) -> ExitCode {
    if !HOST_OPENER {
        let hosts: Vec<String> = std::env::var(HOSTS_ENV)
            .unwrap_or_default()
            .split(',')
            .map(String::from)
            .collect();
        return match print_link(url, &hosts) {
            Ok(line) => {
                eprintln!("{line}");
                // npm `open` spawns xdg-open with stdio ignored, so stderr is
                // lost there; the terminal, if the process still has one, is not.
                if !std::io::stderr().is_terminal()
                    && let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty")
                {
                    let _ = writeln!(tty, "{line}");
                }
                // Nothing was opened. A nonzero exit lets OpenCode 1.19 report
                // the open as failed (mcp.browser.open.failed) instead of
                // waiting on a browser that never appears.
                ExitCode::FAILURE
            }
            Err(line) => {
                eprintln!("{line}");
                ExitCode::FAILURE
            }
        };
    }
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!("cplt mcp-open-url: {SOCKET_ENV} is not set; run inside a cplt session");
        return ExitCode::FAILURE;
    };
    // A newline would end the line protocol early; the broker refuses it too.
    if url.contains(['\n', '\r']) {
        eprintln!("cplt mcp-open-url: denied: URL must be printable ASCII");
        return ExitCode::FAILURE;
    }
    let Ok(mut stream) = UnixStream::connect(&socket) else {
        eprintln!("cplt mcp-open-url: cannot reach the broker; open this URL yourself: {url}");
        return ExitCode::FAILURE;
    };
    if write!(stream, "{OP_LINE}\n{url}\n").is_err() {
        return ExitCode::FAILURE;
    }
    let mut answer = String::new();
    let _ = std::io::BufReader::new(stream).read_line(&mut answer);
    match answer.trim_end() {
        "ok" => ExitCode::SUCCESS,
        other => {
            eprintln!("cplt mcp-open-url: {other}");
            ExitCode::FAILURE
        }
    }
}

/// The allowed hosts, comma-separated, for the Linux shim.
const HOSTS_ENV: &str = "CPLT_OPEN_URL_HOSTS";

/// Linux: the line to show instead of opening `url`. The shim prints only an
/// allowed URL, and `check` refuses control bytes. This is not a boundary: the
/// agent can run `cplt mcp-open-url` with its own `CPLT_OPEN_URL_HOSTS`, and it
/// can print any text itself. Never spawns.
fn print_link(url: &str, hosts: &[String]) -> Result<String, String> {
    match check(url, hosts) {
        Ok(()) => Ok(format!(
            "cplt: open this link in your browser to log in: {url}"
        )),
        Err(why) => Err(format!("cplt: not showing the link: {why}")),
    }
}

/// The shim script. One `https://` argument goes to the broker; anything
/// else runs the real opener, if there is one, as before.
#[must_use]
pub fn shim_script(cplt: &str, socket: &str, hosts: &[String], real: Option<&str>) -> String {
    let fallback = match real {
        Some(r) => format!("exec {} \"$@\"", sh_quote(r)),
        None => "echo \"cplt: only https URLs are opened in this session\" >&2; exit 1".into(),
    };
    format!(
        "#!/bin/sh\n\
         if [ \"$#\" -eq 1 ]; then case \"$1\" in https://*) \
         exec env {SOCKET_ENV}={} {HOSTS_ENV}={} {} mcp-open-url \"$1\" ;; esac; fi\n\
         {fallback}\n",
        sh_quote(socket),
        sh_quote(&hosts.join(",")),
        sh_quote(cplt),
    )
}

fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shim names this platform's URL openers answer to.
pub const SHIM_NAMES: &[&str] = if cfg!(target_os = "macos") {
    &["open"]
} else {
    &["xdg-open"]
};

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
        vec!["fgw.example".into()]
    }

    #[test]
    fn accepts_allowed_hosts() {
        for u in [
            "https://FGW.example/authorize?state=y",
            "https://fgw.example:443/x",
            "https://fgw.example",
            "https://fgw.example?x=1",
            "https://fgw.example#f",
        ] {
            assert_eq!(check(u, &hosts()), Ok(()), "{u}");
        }
    }

    #[test]
    fn rejects_each_rule() {
        let long = format!("https://fgw.example/{}", "a".repeat(MAX_LEN));
        for (u, why) in [
            ("http://fgw.example/", "URL must be https"),
            ("HTTPS://fgw.example/", "URL must be https"),
            ("file:///etc/passwd", "URL must be https"),
            ("javascript:alert(1)", "URL must be https"),
            ("https://evil.example/", "host not allowed"),
            ("https://fgw.example.evil/", "host not allowed"),
            ("https://sub.fgw.example/", "host not allowed"),
            ("https://fgw.example./", "host not allowed"),
            (
                "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x",
                "host not allowed",
            ),
            ("https://xn--fgw-example/", "host not allowed"),
            ("https://user@fgw.example/", "userinfo in URL"),
            ("https://evil.example@fgw.example/", "userinfo in URL"),
            ("https://fgw.example:8443/", "port other than 443"),
            ("https://fgw.example:/", "port other than 443"),
            ("https://fgw.example:443:443/", "port other than 443"),
            ("https://fgw%2eexample/", "percent-encoded host"),
            ("https://[::1]/", "IP literal host"),
            ("https://f\u{e6}w.example/", "URL must be printable ASCII"),
            ("https://fgw.example/\n", "URL must be printable ASCII"),
            ("https://fgw.example/\u{7f}", "URL must be printable ASCII"),
            ("https://fgw.example/ x", "URL must be printable ASCII"),
            ("https://fgw.example\\@evil.example/", "backslash in URL"),
            (long.as_str(), "URL too long"),
        ] {
            assert_eq!(check(u, &hosts()), Err(why), "{u:?}");
        }
    }

    /// #1091: `allow_private_domains` entries match the host and its
    /// subdomains, as the proxy does, and nothing else.
    #[test]
    fn private_domains_allow_host_and_subdomains_only() {
        let d = private_domain_entries(&["Intern.Dev.Nav.No.".into(), String::new()]);
        assert_eq!(d, vec![".intern.dev.nav.no".to_string()]);
        for u in [
            "https://intern.dev.nav.no/",
            "https://fleet-gateway.intern.dev.nav.no/authorize?x=1",
            "https://A.B.INTERN.DEV.NAV.NO:443/",
        ] {
            assert_eq!(check(u, &d), Ok(()), "{u}");
        }
        for (u, why) in [
            ("https://evilintern.dev.nav.no/", HOST_NOT_ALLOWED),
            ("https://dev.nav.no/", HOST_NOT_ALLOWED),
            ("https://intern.dev.nav.no.evil/", HOST_NOT_ALLOWED),
            ("https://xn--intrn-dev-nav-no/", HOST_NOT_ALLOWED),
            (
                "http://fleet-gateway.intern.dev.nav.no/",
                "URL must be https",
            ),
            ("javascript://intern.dev.nav.no/", "URL must be https"),
            ("https://u@intern.dev.nav.no/", "userinfo in URL"),
            (
                "https://int\u{e9}rn.dev.nav.no/",
                "URL must be printable ASCII",
            ),
            ("https://x.intern%2edev.nav.no/", "percent-encoded host"),
            (
                "https://intern.dev.nav.no/\u{1b}[2J",
                "URL must be printable ASCII",
            ),
        ] {
            assert_eq!(check(u, &d), Err(why), "{u:?}");
        }
    }

    #[test]
    fn refusal_names_the_host_and_the_fix() {
        assert_eq!(
            refusal("https://Gh.Example:443/login?x", HOST_NOT_ALLOWED),
            "denied: gh.example is not allowed to open in the host browser. To allow it: cplt config set proxy.allow_private_domains gh.example"
        );
        assert_eq!(
            refusal("http://x/", "URL must be https"),
            "denied: URL must be https"
        );
    }

    #[test]
    fn no_hosts_without_an_oauth_spec() {
        let none = allowed_hosts(std::iter::empty());
        assert!(none.is_empty());
        assert!(check("https://login.microsoftonline.com/", &none).is_err());
    }

    #[test]
    fn limiter_caps_rate_and_outstanding_openers() {
        let l = Limiter::default();
        let t = Instant::now();
        let busy = l.take(t).unwrap();
        assert_eq!(l.take(t).err(), Some("another URL is still being opened"));
        busy.store(false, Ordering::Release);
        l.take(t).unwrap().store(false, Ordering::Release);
        l.take(t).unwrap().store(false, Ordering::Release);
        assert_eq!(
            l.take(t).err(),
            Some("rate limit: too many URLs opened this minute")
        );
        l.take(t + WINDOW).unwrap();
    }

    fn write_policy(roots: &[&Path]) -> LandlockPolicy {
        use crate::sandbox::FsAccess;
        LandlockPolicy {
            fs_rules: roots
                .iter()
                .map(|r| FsRule {
                    path: r.to_path_buf(),
                    access: FsAccess {
                        read: true,
                        write: true,
                        ..FsAccess::default()
                    },
                    nofollow: false,
                })
                .collect(),
            net_rules: Vec::new(),
            restrict_net_connect: true,
            bind_rules: Vec::new(),
            restrict_net_bind: false,
            proxy_forced: false,
            home_dir: PathBuf::from("/h"),
            precreate_dirs: vec![],
            plain_file: None,
        }
    }

    #[test]
    fn opener_config_writable_finds_covering_roots() {
        let h = Path::new("/h");
        let w = |roots: &[&str]| {
            let roots: Vec<&Path> = roots.iter().map(Path::new).collect();
            opener_config_writable(&write_policy(&roots), h)
        };
        assert_eq!(w(&["/h/proj"]), None);
        assert_eq!(w(&["/h"]), Some("/h/Library/Preferences".into()));
        assert_eq!(
            w(&["/h/Library/Preferences/com.apple.LaunchServices"]),
            Some("/h/Library/Preferences".into())
        );
        // An implicit grant beside it, like ~/Library/Caches, does not count.
        assert_eq!(w(&["/h/Library/Caches"]), None);
    }

    #[test]
    fn opener_config_writable_resolves_symlinks() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, repo) = (t.join("home"), t.join("repo"));
        std::fs::create_dir_all(repo.join("prefs")).unwrap();
        std::fs::create_dir_all(home.join("Library")).unwrap();
        let ask = |roots: &[&Path]| opener_config_writable(&write_policy(roots), &home);
        assert_eq!(ask(&[&repo]), None);
        // Preferences linked into the writable repo.
        symlink(repo.join("prefs"), home.join("Library/Preferences")).unwrap();
        assert_eq!(ask(&[&repo]), Some(home.join("Library/Preferences")));
        // A writable root given through a symlink.
        std::fs::remove_file(home.join("Library/Preferences")).unwrap();
        symlink(&home, t.join("alias")).unwrap();
        assert_eq!(
            ask(&[&t.join("alias")]),
            Some(home.join("Library/Preferences"))
        );
    }

    /// Two hops: Preferences -> dotfiles/prefs -> elsewhere. Only the middle
    /// link sits in a writable tree; the agent can repoint it.
    #[test]
    fn opener_config_writable_catches_a_writable_middle_hop() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, dotfiles, elsewhere) = (t.join("home"), t.join("dotfiles"), t.join("elsewhere"));
        for d in [&home.join("Library"), &dotfiles, &elsewhere] {
            std::fs::create_dir_all(d).unwrap();
        }
        symlink(&elsewhere, dotfiles.join("prefs")).unwrap();
        symlink(dotfiles.join("prefs"), home.join("Library/Preferences")).unwrap();
        let ask = |roots: &[&Path]| opener_config_writable(&write_policy(roots), &home);
        assert_eq!(ask(&[&t.join("proj")]), None);
        assert_eq!(ask(&[&dotfiles]), Some(home.join("Library/Preferences")));
        // The same through a link inside Preferences.
        std::fs::remove_file(home.join("Library/Preferences")).unwrap();
        std::fs::create_dir(home.join("Library/Preferences")).unwrap();
        symlink(
            dotfiles.join("prefs"),
            home.join("Library/Preferences/com.apple.LaunchServices"),
        )
        .unwrap();
        assert_eq!(ask(&[&dotfiles]), Some(home.join("Library/Preferences")));
    }

    #[test]
    fn opener_config_writable_enumerates_symlinked_dir() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, d, e, repo) = (t.join("home"), t.join("d"), t.join("e"), t.join("repo"));
        for dir in [&home.join("Library/Preferences"), &d, &e, &repo] {
            std::fs::create_dir_all(dir).unwrap();
        }
        symlink(
            &d,
            home.join("Library/Preferences/com.apple.LaunchServices"),
        )
        .unwrap();

        let ask = |roots: &[&Path]| opener_config_writable(&write_policy(roots), &home);
        // Read-only target directory with no writable entries or links -> allowed.
        assert_eq!(ask(&[&repo]), None);

        // Regular file inside D covered by a write rule (no symlink inside D).
        let direct_plist = d.join("com.apple.LaunchServices.secure.plist");
        std::fs::write(&direct_plist, "").unwrap();
        assert_eq!(
            ask(&[&direct_plist]),
            Some(home.join("Library/Preferences"))
        );

        // Symlink inside D pointing to a writable path (and dangling target under writable repo).
        let dangling = d.join("missing.plist");
        symlink(repo.join("missing.plist"), &dangling).unwrap();
        assert_eq!(ask(&[&repo]), Some(home.join("Library/Preferences")));
        std::fs::remove_file(&dangling).unwrap();

        symlink(
            repo.join("ls.plist"),
            d.join("com.apple.LaunchServices.plist"),
        )
        .unwrap();
        assert_eq!(ask(&[&repo]), Some(home.join("Library/Preferences")));

        // Nested symlinked directory: Preferences/ls -> D, D/sub -> E, E/item -> repo/item.
        std::fs::remove_file(d.join("com.apple.LaunchServices.plist")).unwrap();
        symlink(&e, d.join("sub")).unwrap();
        symlink(repo.join("item"), e.join("item")).unwrap();
        assert_eq!(ask(&[&repo]), Some(home.join("Library/Preferences")));
    }

    #[test]
    fn opener_config_writable_handles_cycles_and_hostile_entries() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let t = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, d, repo) = (t.join("home"), t.join("d"), t.join("repo"));
        let prefs = home.join("Library/Preferences");
        for dir in [&prefs, &d, &repo] {
            std::fs::create_dir_all(dir).unwrap();
        }
        symlink(&d, prefs.join("com.apple.LaunchServices")).unwrap();
        // Cycles: back to Preferences, self-loop, mutual symlink loop.
        symlink(&prefs, d.join("back")).unwrap();
        symlink(".", d.join("self_dir")).unwrap();
        symlink("b", d.join("a")).unwrap();
        symlink("a", d.join("b")).unwrap();
        // Hostile entries: FIFO, symlink to FIFO, dangling symlink to read-only path.
        let fifo = d.join("fifo");
        crate::untrusted::tests::mkfifo(&fifo);
        symlink(&fifo, d.join("link_to_fifo")).unwrap();
        symlink("/nonexistent/safe", d.join("dangling")).unwrap();

        let (home_c, repo_c, prefs_c) = (home.clone(), repo.clone(), prefs.clone());
        let res = crate::untrusted::tests::bounded(move || {
            opener_config_writable(&write_policy(&[&repo_c]), &home_c)
        });
        assert_eq!(res, None);

        // A writable link alongside cycles and FIFOs is still caught.
        symlink(repo.join("evil.plist"), d.join("evil.plist")).unwrap();
        let res = crate::untrusted::tests::bounded(move || {
            opener_config_writable(&write_policy(&[&repo]), &home)
        });
        assert_eq!(res, Some(prefs_c));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn opener_config_writable_catches_var_folders_links() {
        use std::os::unix::fs::symlink;
        let target_dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/target"));
        std::fs::create_dir_all(target_dir).unwrap();
        let tmp = tempfile::tempdir_in(target_dir).unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, project, d) = (root.join("home"), root.join("project"), root.join("d"));
        let prefs = home.join("Library/Preferences");
        for dir in [&prefs, &project, &d] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let cfg = crate::sandbox::SandboxConfig {
            project_dir: &project,
            home_dir: &home,
            extra_read: &[],
            extra_write: &[],
            extra_exec: &[],
            extra_socket: &[],
            extra_deny: &[],
            named_roots: &[],
            named_root_git_dirs: &[],
            managed_worktree_root: None,
            worktree_socket: None,
            mcp_socket: None,
            restrict_oauth_bind: false,
            oauth_port_claimed: false,
            existing_home_tool_dirs: Some(&[]),
            existing_app_dirs: Some(&[]),
            extra_ports: &[],
            localhost_ports: &[],
            proxy_port: None,
            proxy_forced: false,
            allow_env_files: false,
            allow_localhost_any: false,
            scratch_dir: None,
            playwright_socket_dir: None,
            allow_tmp_exec: false,
            copilot_install_dir: None,
            copilot_cache_env: &crate::sandbox::no_cache_env,
            java_home: None,
            dotnet_root: None,
            git_hooks_path: None,
            git_common_dir: None,
            root_agents_md: None,
            allow_gpg_signing: false,
            deny_clipboard: false,
            deny_dns: false,
            netns: false,
            deny_nested_git: false,
            refuse_cache_exec_links: false,
            refuse_unenforced: false,
            proxy_enabled: false,
            deny_key_files_by_extension: false,
            protect_pnpm_config: true,
            deny_copilot_dir_exec: true,
            allow_copilot_host_persistence: false,
            mask_missing_deny_paths: false,
            allow_jvm_attach: false,
            allow_msbuild: false,
            allow_docker: false,
            allow_rootless_docker: false,
            electron_app_dir: None,
            agent: crate::agent::Agent::Copilot,
            agent_dirs: &[],
            allow_cache_exec: &[],
            allow_cache_exec_any: false,
            allow_browser: false,
            use_bubblewrap: None,
            allow_git_config_write: false,
            keychain_substitute: None,
        };
        let policy = crate::sandbox::generate_policy(&cfg);

        // Read-only symlinked dir under Preferences -> allowed.
        let ls_link = prefs.join("com.apple.LaunchServices");
        symlink(&d, &ls_link).unwrap();
        assert_eq!(opener_config_writable(&policy, &home), None);

        // Link inside D pointing into /var/folders (writable in SBPL) -> caught.
        let vf_dir = tempfile::tempdir().unwrap();
        let vf_target = vf_dir.path().join("ls.plist");
        std::fs::write(&vf_target, "").unwrap();
        symlink(&vf_target, d.join("com.apple.LaunchServices.plist")).unwrap();
        assert_eq!(opener_config_writable(&policy, &home), Some(prefs.clone()));

        // Direct link under Preferences into /private/var/folders -> caught.
        std::fs::remove_file(d.join("com.apple.LaunchServices.plist")).unwrap();
        std::fs::remove_file(&ls_link).unwrap();
        let canon_vf = std::fs::canonicalize(vf_dir.path()).unwrap();
        symlink(&canon_vf, &ls_link).unwrap();
        assert_eq!(opener_config_writable(&policy, &home), Some(prefs));
    }

    #[test]
    fn collect_links_flags_truncation_over_entry_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        for i in 0..5 {
            std::fs::write(dir.join(format!("f{i}")), "").unwrap();
        }
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        assert!(!collect_links(&dir, 4, 5, &mut out, &mut visited));
        out.clear();
        visited.clear();
        assert!(collect_links(&dir, 4, 4, &mut out, &mut visited));
    }

    #[test]
    fn opener_config_writable_fails_closed_at_depth_limit() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let (home, outside, repo) = (root.join("home"), root.join("outside"), root.join("repo"));
        let prefs = home.join("Library/Preferences");
        for dir in [&prefs, &outside, &repo] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let secure_plist = outside.join("secure.plist");
        std::fs::write(&secure_plist, "").unwrap();

        // Depth 3 (`a/b/c/link -> outside`) still scans `outside` (`rem_depth == 0`)
        // and catches a write grant only on `outside/secure.plist`.
        let c = prefs.join("a/b/c");
        std::fs::create_dir_all(&c).unwrap();
        let link_in_c = c.join("link");
        symlink(&outside, &link_in_c).unwrap();
        assert_eq!(opener_config_writable(&write_policy(&[&repo]), &home), None);
        assert_eq!(
            opener_config_writable(&write_policy(&[&secure_plist]), &home),
            Some(prefs.clone())
        );

        // An already-visited cycle at `rem_depth == 0` (`a/b/c/d/back -> prefs`)
        // does not falsely trigger depth truncation.
        std::fs::remove_file(&link_in_c).unwrap();
        let d = c.join("d");
        std::fs::create_dir_all(&d).unwrap();
        let back = d.join("back");
        symlink(&prefs, &back).unwrap();
        assert_eq!(opener_config_writable(&write_policy(&[&repo]), &home), None);
        std::fs::remove_file(&back).unwrap();

        // Depth 4 (`a/b/c/d/link -> outside`) hits `rem_depth == 0` on `d`, leaving
        // `outside` unchecked; must fail closed even for grants only on `outside/secure.plist`
        // or unrelated roots.
        let link_in_d = d.join("link");
        symlink(&outside, &link_in_d).unwrap();
        let mut out = Vec::new();
        let mut visited = HashSet::new();
        assert!(collect_links(
            &prefs,
            4,
            MAX_COLLECT_ENTRIES,
            &mut out,
            &mut visited
        ));
        assert_eq!(
            opener_config_writable(&write_policy(&[&secure_plist]), &home),
            Some(prefs.clone())
        );
        assert_eq!(
            opener_config_writable(&write_policy(&[&repo]), &home),
            Some(prefs.clone())
        );
        std::fs::remove_file(&link_in_d).unwrap();

        // Ordinary directory at depth 4 (`a/b/c/d/sub`) also fails closed because
        // symlinks inside `sub` cannot be inspected.
        let sub = d.join("sub");
        std::fs::create_dir(&sub).unwrap();
        symlink(repo.join("evil.plist"), sub.join("evil.plist")).unwrap();
        out.clear();
        visited.clear();
        assert!(collect_links(
            &prefs,
            4,
            MAX_COLLECT_ENTRIES,
            &mut out,
            &mut visited
        ));
        assert_eq!(
            opener_config_writable(&write_policy(&[&repo]), &home),
            Some(prefs)
        );
    }

    /// Owner decision 2026-11-17: no host opener off macOS, ever.
    #[test]
    fn linux_never_spawns_and_prints_only_allowed_urls() {
        assert_eq!(opener(true), Some("/usr/bin/open".into()));
        assert_eq!(opener(false), None);
        assert_eq!(HOST_OPENER, cfg!(target_os = "macos"));
        assert_eq!(
            print_link("https://fgw.example/a?b=c", &hosts()),
            Ok("cplt: open this link in your browser to log in: https://fgw.example/a?b=c".into())
        );
        for bad in [
            "https://evil.example/",
            "https://fgw.example/\x1b[2J",
            "https://fgw.example/\u{1b}]8;;https://evil.example\u{7}",
            "https://fgw.example/\nfake",
        ] {
            let e = print_link(bad, &hosts()).unwrap_err();
            assert!(e.starts_with("cplt: not showing the link: "), "{e}");
            assert!(!e.contains("evil") && !e.contains('\u{1b}'), "{e}");
        }
    }

    #[test]
    fn allowed_hosts_are_only_remote_url_hosts() {
        static OAUTH: crate::mcp_broker::credential::Credential =
            crate::mcp_broker::credential::Credential {
                name: OAUTH_CREDENTIAL,
                command: None,
                probe: None,
                keychain: false,
                write_dirs: &[],
                linux_write_dirs: &[],
                linux_read_paths: &[],
            };
        let spec = Spec {
            id: "x".into(),
            file: PathBuf::new(),
            credential: &OAUTH,
            command: vec!["https://cmd.example/mcp".into()],
            program: PathBuf::new(),
            remote: Some("https://FGW.example/mcp".into()),
            remote_headers: Vec::new(),
            timeout_secs: 600,
            egress_hosts: vec![
                "fgw.example".into(),
                "cmd.example".into(),
                "login.microsoftonline.com".into(),
            ],
            allow: std::collections::BTreeSet::default(),
            graphql: std::collections::BTreeSet::default(),
            login: None,
        };
        assert_eq!(allowed_hosts([&spec].into_iter()), vec!["fgw.example"]);
        // A remote host missing from egressHosts is not allowed.
        let mut off = spec.clone();
        off.egress_hosts = vec!["cmd.example".into()];
        assert!(allowed_hosts([&off].into_iter()).is_empty());
    }

    #[test]
    fn opener_env_is_scrubbed() {
        let get = |k: &str| {
            Some(std::ffi::OsString::from(match k {
                "PATH" => "/agent/bin",
                _ => "v",
            }))
        };
        let env = opener_env(Path::new("/h"), &get);
        let keys: Vec<_> = env.iter().map(|(k, _)| *k).collect();
        let path = &env.iter().find(|(k, _)| *k == "PATH").unwrap().1;
        assert_eq!(
            path,
            &std::ffi::OsString::from(crate::git::TRUSTED_BIN_DIRS.join(":"))
        );
        for k in [
            "CPLT_MCP_SOCKET",
            "GITHUB_TOKEN",
            "LD_PRELOAD",
            "BROWSER",
            "GIO_EXTRA_MODULES",
        ] {
            assert!(!keys.contains(&k), "{k} leaked: {keys:?}");
        }
        assert!(keys.contains(&"HOME") && keys.contains(&"LANG"));
        assert!(!keys.contains(&"DISPLAY") && !keys.contains(&"XDG_CONFIG_HOME"));
    }

    #[test]
    fn shim_forwards_one_https_url_and_quotes_paths() {
        let s = shim_script("/opt/c'p", "/tmp/s", &hosts(), Some("/usr/bin/open"));
        assert!(s.contains("'/opt/c'\\''p' mcp-open-url \"$1\""), "{s}");
        assert!(s.contains("CPLT_MCP_SOCKET='/tmp/s'"), "{s}");
        assert!(
            s.contains(&format!("CPLT_OPEN_URL_HOSTS='{}'", hosts().join(","))),
            "{s}"
        );
        assert!(s.contains("exec '/usr/bin/open' \"$@\""), "{s}");
        assert!(shim_script("c", "s", &[], None).contains("exit 1"));
    }

    #[test]
    fn serve_answers_and_never_opens_a_denied_url() {
        let log = super::super::Log {
            level: crate::proxy::ProxyLogLevel::default(),
            file: None,
        };
        let mut out = Vec::new();
        serve(
            &mut "https://evil.example/\n".as_bytes(),
            &mut out,
            &hosts(),
            &Limiter::default(),
            Path::new("/h"),
            &log,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "denied: evil.example is not allowed to open in the host browser. To allow it: cplt config set proxy.allow_private_domains evil.example\n"
        );
    }
}
