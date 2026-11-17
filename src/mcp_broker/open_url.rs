//! `open_url`: the broker opens an OAuth authorize URL in the host browser
//! for a sandboxed MCP client (owner decision 2026-11-17, #910).
//!
//! The sandbox side is a PATH shim named `open` (macOS) or `xdg-open`
//! (Linux), because OpenCode opens URLs through the npm `open` package, which
//! ignores `BROWSER`. The shim runs `cplt mcp-open-url <url>`, which sends the
//! URL to the broker. The broker checks it here and runs the platform opener
//! with the URL as one argv entry, never through a shell.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use super::SOCKET_ENV;
use super::spec::Spec;

/// First line a client sends for this op. Spec ids cannot contain `:`.
pub(crate) const OP_LINE: &str = "cplt:open_url";
/// Always allowed: the Entra ID login host.
const LOGIN_HOST: &str = "login.microsoftonline.com";
/// An authorize URL with PKCE and state fits well inside this.
const MAX_LEN: usize = 4096;
/// The credential of a remote spec that runs OAuth (#1020).
const OAUTH_CREDENTIAL: &str = "oauth";

/// Hosts a URL may name: the login host plus each oauth spec's `egressHosts`.
/// No new config key: the spec already names where its OAuth flow goes.
pub(crate) fn allowed_hosts<'a>(specs: impl Iterator<Item = &'a Spec>) -> Vec<String> {
    let mut hosts = vec![LOGIN_HOST.to_string()];
    for s in specs.filter(|s| s.credential.name == OAUTH_CREDENTIAL) {
        hosts.extend(s.egress_hosts.iter().map(|h| h.to_ascii_lowercase()));
    }
    hosts
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
    log: &super::Log,
) {
    let Some(url) = super::runtime::read_line(reader, MAX_LEN as u64 + 2) else {
        return;
    };
    let answer = match check(&url, hosts) {
        Err(why) => {
            log.line("open_url", &format!("DENIED {why}"));
            format!("denied: {why}")
        }
        Ok(()) => match opener().map(|o| spawn_opener(&o, &url)) {
            Some(Ok(())) => {
                log.line("open_url", "ALLOWED");
                "ok".to_string()
            }
            Some(Err(e)) => {
                log.line("open_url", &format!("FAIL {e}"));
                "failed: cannot run the opener".to_string()
            }
            None => {
                log.line("open_url", "FAIL no opener");
                "failed: no opener on the host".to_string()
            }
        },
    };
    let _ = writeln!(reply, "{answer}");
}

fn spawn_opener(opener: &Path, url: &str) -> std::io::Result<()> {
    // `opener` is an absolute path from `opener()`, never a PATH lookup.
    #[allow(clippy::disallowed_methods)]
    let mut child = Command::new(opener)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Reap it without holding the connection.
    std::thread::spawn(move || child.wait());
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
        vec![LOGIN_HOST.into(), "fgw.example".into()]
    }

    #[test]
    fn accepts_allowed_hosts() {
        for u in [
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=x&state=y",
            "https://LOGIN.microsoftonline.com/",
            "https://login.microsoftonline.com:443/x",
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
            ("https://login.microsoftonline.com./", "host not allowed"),
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
    fn only_the_login_host_without_an_oauth_spec() {
        let only = allowed_hosts(std::iter::empty());
        assert_eq!(only, vec![LOGIN_HOST.to_string()]);
        assert!(check("https://fgw.example/", &only).is_err());
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
            &log,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "denied: host not allowed\n"
        );
    }
}
