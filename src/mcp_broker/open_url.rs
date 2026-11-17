//! `open_url`: the broker opens an OAuth authorize URL in the host browser
//! for a sandboxed MCP client (owner decision 2026-11-17, #910).
//!
//! The sandbox side is a PATH shim named `open` (macOS) or `xdg-open`
//! (Linux), because OpenCode opens URLs through the npm `open` package, which
//! ignores `BROWSER`. The shim runs `cplt mcp-open-url <url>`, which sends the
//! URL to the broker. The broker checks it here and runs the platform opener
//! with the URL as one argv entry, never through a shell.

use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::SOCKET_ENV;
use super::spec::Spec;

/// First line a client sends for this op. Spec ids cannot contain `:`.
pub(crate) const OP_LINE: &str = "cplt:open_url";
/// An authorize URL with PKCE and state fits well inside this.
const MAX_LEN: usize = 4096;
/// The credential of a remote spec that runs OAuth (#1020).
const OAUTH_CREDENTIAL: &str = "oauth";

/// Opens per [`WINDOW`], and the window itself.
const MAX_OPENS: usize = 3;
const WINDOW: Duration = Duration::from_secs(60);

/// Hosts a URL may name: each oauth spec's `egressHosts`, the fleet gateway.
/// No new config key: the spec already names where its OAuth flow goes.
/// The Entra login host is deliberately absent (owner decision 2026-11-17):
/// an authorize URL for a first-party client_id with a loopback redirect
/// would complete silently under browser SSO and hand the code to whoever
/// listens on that port. The gateway redirects the browser to Entra itself.
/// Empty means the op is off.
pub(crate) fn allowed_hosts<'a>(specs: impl Iterator<Item = &'a Spec>) -> Vec<String> {
    specs
        .filter(|s| s.credential.name == OAUTH_CREDENTIAL)
        .flat_map(|s| s.egress_hosts.iter().map(|h| h.to_ascii_lowercase()))
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
    if hosts.contains(&host) {
        Ok(())
    } else {
        Err("host not allowed")
    }
}

/// On Linux `xdg-open` picks the handler from `mimeapps.list` and `.desktop`
/// files under the user's XDG dirs. If the sandbox can write one of those, it
/// can make the host run any command for an allowed URL. Returns the first
/// such path among `writable` roots; the launcher then turns the op off.
#[must_use]
pub fn opener_config_writable(
    home: &Path,
    writable: &[&Path],
    get: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let xdg = |k: &str, d: &str| {
        get(k)
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(d))
    };
    let mime = xdg("XDG_CONFIG_HOME", ".config").join("mimeapps.list");
    let apps = xdg("XDG_DATA_HOME", ".local/share").join("applications");
    writable.iter().find_map(|w| {
        if mime.starts_with(w) {
            Some(mime.clone())
        } else if apps.starts_with(w) || w.starts_with(&apps) {
            Some(apps.clone())
        } else {
            None
        }
    })
}

/// The platform opener, resolved outside the agent's reach.
fn opener() -> Option<std::path::PathBuf> {
    if cfg!(target_os = "macos") {
        Some("/usr/bin/open".into())
    } else {
        crate::git::trusted_binary("xdg-open")
    }
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
            log.line("open_url", &format!("DENIED {why}"));
            format!("denied: {why}")
        }
        Ok(busy) => match opener().map(|o| spawn_opener(&o, &url, home, busy)) {
            Some(Ok(())) => {
                log.line("open_url", "ALLOWED");
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
/// (`runtime::host_env`): cleared, then HOME, the trusted PATH so `xdg-open`
/// cannot pick up an agent-planted `gio` or browser, TMPDIR, and only what a
/// desktop opener needs to reach the session and the user's browser choice.
fn opener_env(
    home: &Path,
    get: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(&'static str, std::ffi::OsString)> {
    let mut env = vec![
        ("HOME", home.as_os_str().to_owned()),
        ("PATH", crate::git::TRUSTED_BIN_DIRS.join(":").into()),
        ("TMPDIR", std::env::temp_dir().into_os_string()),
    ];
    let mut keep = vec!["LANG", "LC_ALL"];
    if cfg!(target_os = "linux") {
        keep.extend([
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_RUNTIME_DIR",
            "XDG_CURRENT_DESKTOP",
            "XDG_SESSION_TYPE",
            "XDG_CONFIG_HOME",
            "XDG_CONFIG_DIRS",
            "XDG_DATA_HOME",
            "XDG_DATA_DIRS",
        ]);
    }
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

/// The shim script. One `https://` argument goes to the broker; anything
/// else runs the real opener, if there is one, as before.
#[must_use]
pub fn shim_script(cplt: &str, socket: &str, real: Option<&str>) -> String {
    let fallback = match real {
        Some(r) => format!("exec {} \"$@\"", sh_quote(r)),
        None => "echo \"cplt: only https URLs are opened in this session\" >&2; exit 1".into(),
    };
    format!(
        "#!/bin/sh\n\
         if [ \"$#\" -eq 1 ]; then case \"$1\" in https://*) \
         exec env {SOCKET_ENV}={} {} mcp-open-url \"$1\" ;; esac; fi\n\
         {fallback}\n",
        sh_quote(socket),
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

    #[test]
    fn opener_config_writable_finds_covering_roots() {
        let h = Path::new("/h");
        let none = |_: &str| None;
        let w = |roots: &[&str]| {
            let roots: Vec<&Path> = roots.iter().map(Path::new).collect();
            opener_config_writable(h, &roots, &none)
        };
        assert_eq!(w(&["/h/proj", "/h/.config/opencode"]), None);
        assert_eq!(w(&["/h"]), Some("/h/.config/mimeapps.list".into()));
        assert_eq!(w(&["/h/.config"]), Some("/h/.config/mimeapps.list".into()));
        assert_eq!(
            w(&["/h/.local/share/applications/x"]),
            Some("/h/.local/share/applications".into())
        );
        let xdg = |k: &str| (k == "XDG_CONFIG_HOME").then(|| "/cfg".into());
        assert_eq!(
            opener_config_writable(h, &[Path::new("/cfg")], &xdg),
            Some("/cfg/mimeapps.list".into())
        );
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
        if cfg!(target_os = "linux") {
            assert!(keys.contains(&"DISPLAY") && keys.contains(&"DBUS_SESSION_BUS_ADDRESS"));
        } else {
            assert!(!keys.contains(&"DISPLAY"));
        }
    }

    #[test]
    fn shim_forwards_one_https_url_and_quotes_paths() {
        let s = shim_script("/opt/c'p", "/tmp/s", Some("/usr/bin/open"));
        assert!(s.contains("'/opt/c'\\''p' mcp-open-url \"$1\""), "{s}");
        assert!(s.contains("CPLT_MCP_SOCKET='/tmp/s'"), "{s}");
        assert!(s.contains("exec '/usr/bin/open' \"$@\""), "{s}");
        assert!(shim_script("c", "s", None).contains("exit 1"));
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
            "denied: host not allowed\n"
        );
    }
}
