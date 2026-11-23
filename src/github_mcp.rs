//! GitHub's remote MCP server for OpenCode v2, through a host-side proxy (#797).
//!
//! GitHub's OAuth has no dynamic client registration, so OpenCode cannot log
//! in to `api.githubcopilot.com/mcp` itself, and cplt strips `GH_TOKEN` for
//! it. When the user's own OpenCode config names that server, cplt serves an
//! endpoint at a random secret path on its existing CONNECT proxy port and
//! points the entry at it with `"oauth": false`. No new port is opened: on
//! Linux, Landlock port rules cannot be pinned to loopback, so a new port
//! would be open to every host.
//!
//! The endpoint adds the host's gh token and forwards every request to one
//! fixed upstream, the read-only endpoint, with `X-MCP-Readonly` and
//! `X-MCP-Lockdown` forced on. The token never enters the sandbox through
//! this path; the agent gets a read-only, lockdown view of GitHub.
//!
//! cplt has no TLS stack, so the upstream leg runs through the system `curl`
//! (trusted dirs only), one process per request. The token and the request
//! reach curl on stdin as a config file, never in argv, and `-q` keeps the
//! user's `~/.curlrc` out.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::agent::SecretToken;

use serde_json::{Map, Value};

use crate::proxy::{ProxyLogLevel, UpstreamProxy};

/// The only place requests go, whatever URL the user's entry names.
pub const UPSTREAM: &str = "https://api.githubcopilot.com/mcp/readonly";
const MAX_BODY: usize = 4 * 1024 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;
/// curl's limit on reaching the upstream (or the upstream proxy).
const CONNECT_TIMEOUT_SECS: &str = "10";
/// curl's limit on one whole request, an event stream included, so a stalled
/// upstream cannot hold a proxy connection slot for ever (#1059).
const MAX_TIME_SECS: &str = "600";

/// Running curl children as (owning proxy's shutdown-flag address, PID), so proxy shutdown can kill
/// them (#1059). A PID leaves the set before it is reaped, so it is never a
/// reused PID.
pub(crate) static CHILDREN: std::sync::Mutex<Vec<(usize, u32)>> = std::sync::Mutex::new(Vec::new());

/// Kill the running curl children of one proxy instance, when it shuts down.
/// `owner` is the address of that instance's shutdown flag: unique while the
/// proxy lives, unlike its port, which a new proxy may reuse during shutdown.
pub(crate) fn kill_children(owner: &std::sync::atomic::AtomicBool) {
    let owner = std::ptr::from_ref(owner) as usize;
    let pids = CHILDREN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for &(_, pid) in pids.iter().filter(|(o, _)| *o == owner) {
        if let Ok(pid) = libc::pid_t::try_from(pid) {
            // SAFETY: plain syscall; the PID is unreaped (see CHILDREN).
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// Read exactly `buf.len()` bytes, all within `limit` in total: a per-read
/// timeout alone lets a client trickle a 4 MiB body one byte at a time (#1059).
fn read_body(client: &mut TcpStream, buf: &mut [u8], limit: std::time::Duration) -> bool {
    // `proxy.timeout` is any u64 of seconds: cap it so the sum cannot overflow.
    let deadline = std::time::Instant::now() + limit.min(std::time::Duration::from_secs(86_400));
    let mut done = 0;
    while done < buf.len() {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() || client.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        match client.read(&mut buf[done..]) {
            Ok(0) | Err(_) => return false,
            Ok(n) => done += n,
        }
    }
    true
}

/// Does `url` name GitHub's remote MCP server (full or read-only endpoint)?
pub fn is_github_mcp_url(url: &str) -> bool {
    let url = url.trim().to_ascii_lowercase();
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let rest = rest.split(['?', '#']).next().unwrap_or_default();
    let rest = rest.trim_end_matches('/');
    let rest = rest.replacen("api.githubcopilot.com:443/", "api.githubcopilot.com/", 1);
    rest == "api.githubcopilot.com/mcp" || rest == "api.githubcopilot.com/mcp/readonly"
}

/// An entry to route: (`true` for v2's `mcp.servers.<name>`, `false` for the
/// legacy `mcp.<name>` that v2 still reads; the name).
pub type Entry = (bool, String);

/// The entries in `config` that point at GitHub's MCP.
pub fn github_servers(config: &Value) -> Vec<Entry> {
    let is_github = |s: &Value| {
        s.get("url")
            .and_then(Value::as_str)
            .is_some_and(is_github_mcp_url)
    };
    let mut out = Vec::new();
    for (v2, map) in [
        (true, config.pointer("/mcp/servers")),
        (false, config.get("mcp")),
    ] {
        for (name, s) in map.and_then(Value::as_object).into_iter().flatten() {
            if is_github(s) {
                out.push((v2, name.clone()));
            }
        }
    }
    out
}

/// The `OPENCODE_CONFIG_CONTENT` value: `existing` with each entry pointed at
/// `proxy_url` and its OAuth off, in the shape it was found in. OpenCode
/// deep-merges this over the files, so the rest of each entry (`enabled`,
/// `timeout`) stays the user's. `None` when `existing` is not a JSON object:
/// cplt will not replace a value it cannot read.
pub fn overlay(existing: Option<&str>, entries: &[Entry], proxy_url: &str) -> Option<String> {
    let mut root = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        None => Map::new(),
        Some(s) => match serde_json::from_str(s).ok()? {
            Value::Object(m) => m,
            _ => return None,
        },
    };
    for (v2, name) in entries {
        let mut parent = object_at(&mut root, "mcp")?;
        if *v2 {
            parent = object_at(parent, "servers")?;
        }
        let entry = object_at(parent, name)?;
        entry.insert("type".into(), "remote".into());
        entry.insert("url".into(), proxy_url.into());
        entry.insert("oauth".into(), false.into());
    }
    Some(Value::Object(root).to_string())
}

fn object_at<'a>(map: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
}

/// The GitHub MCP entries in the config files the user controls: the config
/// dirs (`$XDG_CONFIG_HOME/opencode`, `OPENCODE_CONFIG_DIR`), `OPENCODE_CONFIG`
/// and `OPENCODE_CONFIG_CONTENT`. Project files are agent-writable and never
/// count: an agent must not be able to switch on spending the user's token.
/// `nav-pilot mcp enable --client opencode` writes the user config dir.
pub fn configured_servers(
    dirs: &[PathBuf],
    config_file: Option<&Path>,
    content: Option<&str>,
) -> Vec<Entry> {
    let mut names: Vec<Entry> = user_configs(dirs, config_file, content)
        .iter()
        .flat_map(github_servers)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// The user's OpenCode configs, parsed: `config.json`, `opencode.json` and
/// `opencode.jsonc` in each of `dirs`, then `config_file`, then `content`.
/// Read as untrusted (no symlinks, size cap); unreadable or invalid ones are
/// skipped. Project config is never among them.
pub fn user_configs(
    dirs: &[PathBuf],
    config_file: Option<&Path>,
    content: Option<&str>,
) -> Vec<Value> {
    let mut files: Vec<PathBuf> = dirs
        .iter()
        .flat_map(|d| ["config.json", "opencode.json", "opencode.jsonc"].map(|f| d.join(f)))
        .collect();
    files.extend(config_file.map(Path::to_path_buf));
    let mut texts: Vec<String> = files
        .iter()
        .filter_map(|f| {
            crate::untrusted::read_untrusted(f, CONFIG_LIMIT)
                .ok()
                .flatten()
        })
        .collect();
    texts.extend(content.map(str::to_string));
    texts
        .iter()
        .filter_map(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .collect()
}

/// Where request lines go: the proxy's log level and `--proxy-log` file.
pub struct Log {
    pub level: ProxyLogLevel,
    pub file: Option<PathBuf>,
}

impl Log {
    fn line(&self, method: &str, status: &str) {
        let method = method.escape_debug().to_string();
        let status = status.escape_debug().to_string();
        if self.level.should_log(&status) {
            eprintln!(
                "{}[github-mcp]{} {} {method} {UPSTREAM} → {status}",
                crate::ui::color(crate::ui::YELLOW),
                crate::ui::color(crate::ui::RESET),
                crate::proxy::chrono_now()
            );
        }
        if let Some(path) = &self.file
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(
                f,
                "{} {method} {UPSTREAM} {status}",
                crate::proxy::iso_now()
            );
        }
    }
}

/// What the proxy serves at the secret path.
pub struct Endpoint {
    token: SecretToken,
    path: String,
    curl: PathBuf,
    upstream: String,
}

/// ponytail: one endpoint per process, which is one cplt session; a
/// per-proxy field would be needed to serve two.
static ENDPOINT: OnceLock<Endpoint> = OnceLock::new();

/// A fresh secret for the endpoint path.
pub fn new_secret() -> Result<String, String> {
    crate::scratch::generate_session_id()
}

/// Serve the endpoint at `/<secret>` on the running proxy.
pub fn install(token: SecretToken, secret: &str) -> Result<(), String> {
    let curl = crate::git::trusted_binary("curl").ok_or("no curl in the trusted dirs")?;
    install_endpoint(Endpoint {
        token,
        path: format!("/{secret}"),
        curl,
        upstream: UPSTREAM.into(),
    })
}

fn install_endpoint(ep: Endpoint) -> Result<(), String> {
    ENDPOINT
        .set(ep)
        .map_err(|_| "the GitHub MCP endpoint is already set".to_string())
}

/// The endpoint, when `target` is exactly its path. Constant-time, so the
/// secret cannot be guessed a byte at a time.
pub(crate) fn endpoint_for(target: &str) -> Option<&'static Endpoint> {
    let ep = ENDPOINT.get()?;
    let (a, b) = (target.as_bytes(), ep.path.as_bytes());
    // The length is public (a fixed-size secret); only the bytes are compared
    // in constant time.
    if a.len() != b.len() {
        return None;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    (diff == 0).then_some(ep)
}

/// Client headers that never reach upstream: credentials and MCP mode
/// switches are cplt's to set (`X-MCP-Toolsets` only picks tool groups and
/// passes); the rest are hop-by-hop or curl's job.
fn forwarded(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n == "x-mcp-toolsets"
        || !(n.starts_with("x-mcp-")
            || n.starts_with("proxy-")
            || matches!(
                n.as_str(),
                "authorization"
                    | "cookie"
                    | "host"
                    | "content-length"
                    | "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "te"
                    | "trailer"
                    | "upgrade"
                    | "expect"
            ))
}

/// A header name or value that could break out of its line: any control
/// byte but HTAB, or DEL. Checked before anything is quoted for curl.
fn bad_header_byte(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f)
}

/// A quoted curl config value. curl unescapes `\\r`, `\\n` and `\\t` again,
/// so the body round-trips exactly; headers never reach here with a control
/// byte (see [`bad_header_byte`]), and NUL is refused for both.
fn quote(out: &mut Vec<u8>, value: &[u8]) {
    out.push(b'"');
    for &b in value {
        match b {
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'"' => out.extend_from_slice(b"\\\""),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            _ => out.push(b),
        }
    }
    out.extend_from_slice(b"\"\n");
}

/// An RFC 9110 token (`tchar`), the only header name forwarded. curl reads a
/// `header` value starting with `@` as a file of headers, so anything else
/// could make the host curl read local files or add cplt's own mode headers.
/// The name always leads the value, so no value can start a curl special form.
fn header_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The curl config for one request, or `None` for a header with a control
/// byte or a name that is not a token. Upstream, credential and MCP mode come from cplt alone; the client
/// supplies only the method, its other headers and the body.
fn curl_config(
    upstream: &str,
    via: Option<&UpstreamProxy>,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    token: &str,
) -> Option<Vec<u8>> {
    if headers
        .iter()
        .any(|(k, v)| !header_name(k) || bad_header_byte(v))
    {
        return None;
    }
    let mut c = Vec::new();
    let mut opt = |name: &str, value: &[u8]| {
        c.extend_from_slice(name.as_bytes());
        c.extend_from_slice(b" = ");
        quote(&mut c, value);
    };
    opt("url", upstream.as_bytes());
    // The route is set here, never left to curl's env: the token goes direct
    // or through the user's `proxy.upstream`, nowhere else.
    match via {
        Some(u) => {
            opt("proxy", format!("http://{}", u.socket_addr()).as_bytes());
            opt("noproxy", b"");
            if let Some(auth) = &u.proxy_authorization {
                opt(
                    "proxy-header",
                    format!("Proxy-Authorization: Basic {auth}").as_bytes(),
                );
            }
        }
        None => opt("noproxy", b"*"),
    }
    opt("request", method.as_bytes());
    for (k, v) in headers.iter().filter(|(k, _)| forwarded(k)) {
        opt("header", format!("{k}: {v}").as_bytes());
    }
    opt(
        "header",
        format!("Authorization: Bearer {token}").as_bytes(),
    );
    opt("header", b"X-MCP-Readonly: true");
    opt("header", b"X-MCP-Lockdown: true");
    opt("header", b"Expect:");
    if via.is_some() {
        // A bare boolean: curl's config parser refuses a value here.
        c.extend_from_slice(b"proxytunnel\n");
    }
    if !body.is_empty() {
        c.extend_from_slice(b"data-raw = ");
        quote(&mut c, body);
    }
    Some(c)
}

/// curl's stderr for the log: the token replaced before truncation, so a cut
/// can never leave a token prefix behind.
fn redact_stderr(raw: &[u8], token: &str) -> String {
    let s = String::from_utf8_lossy(raw).replace(token, "<token>");
    let mut end = s.len().min(2048);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn reply(stream: &mut TcpStream, status: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

impl Endpoint {
    /// One request, whose head the proxy has read (its size cap, deadline and
    /// connection limit apply); the body is still in `client`. Runs curl and
    /// streams its answer back.
    /// Host and port of the pinned upstream, for the proxy's domain policy.
    pub(crate) fn authority(&self) -> (String, u16) {
        let (scheme, rest) = self.upstream.split_once("://").unwrap_or(("https", ""));
        let auth = rest.split('/').next().unwrap_or_default();
        match auth.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap_or(443)),
            _ => (auth.to_string(), if scheme == "http" { 80 } else { 443 }),
        }
    }

    /// The curl command line; the request itself goes in on stdin.
    fn command(&self) -> Command {
        #[allow(clippy::disallowed_methods)] // resolved trusted path, or a fixture in tests
        let mut cmd = Command::new(&self.curl);
        // -q first: no ~/.curlrc. No redirects; https only for the real upstream.
        cmd.args([
            "-q",
            "-sS",
            "-N",
            "-i",
            "--http1.1",
            "--suppress-connect-headers",
            "--max-redirs",
            "0",
            "--connect-timeout",
            CONNECT_TIMEOUT_SECS,
            "--max-time",
            MAX_TIME_SECS,
            "-K",
            "-",
        ]);
        if self.upstream.starts_with("https://") {
            cmd.args(["--proto", "=https"]);
        }
        // A cleared env: HTTPS_PROXY, ALL_PROXY, NO_PROXY and CURL_* on the host
        // must not decide where the token goes. Only CA locations pass.
        cmd.env_clear();
        for var in ["SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE"] {
            if let Some(v) = std::env::var_os(var) {
                cmd.env(var, v);
            }
        }
        cmd
    }

    pub(crate) fn serve(
        &self,
        mut client: TcpStream,
        head: &[u8],
        log: &Log,
        via: Option<&UpstreamProxy>,
        body_limit: std::time::Duration,
        shutdown: &std::sync::atomic::AtomicBool,
    ) {
        let head = String::from_utf8_lossy(head);
        let mut lines = head.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let method = lines
            .next()
            .and_then(|l| l.split(' ').next())
            .unwrap_or_default()
            .to_string();
        if !matches!(method.as_str(), "GET" | "POST" | "DELETE") {
            reply(&mut client, "405 Method Not Allowed");
            return log.line(&method, "BLOCKED-METHOD");
        }
        let headers: Vec<(String, String)> = lines
            .take_while(|l| !l.is_empty())
            .map(|l| match l.split_once(':') {
                Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
                // A line without a colon is malformed; make it fail the check.
                None => (String::new(), "\u{0}".into()),
            })
            .collect();
        let header = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        if header("transfer-encoding").is_some() {
            reply(&mut client, "411 Length Required");
            return log.line(&method, "FAIL chunked request");
        }
        let len = match header("content-length").map(str::parse::<usize>) {
            None => 0,
            Some(Ok(n)) if n <= MAX_BODY => n,
            _ => {
                reply(&mut client, "413 Content Too Large");
                return log.line(&method, "FAIL body length");
            }
        };
        let mut body = vec![0; len];
        if !read_body(&mut client, &mut body, body_limit) || body.contains(&0) {
            reply(&mut client, "400 Bad Request");
            return log.line(&method, "FAIL bad body");
        }
        let Some(config) = curl_config(
            &self.upstream,
            via,
            &method,
            &headers,
            &body,
            self.token.expose(),
        ) else {
            reply(&mut client, "400 Bad Request");
            return log.line(&method, "FAIL bad header");
        };
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            reply(&mut client, "503 Service Unavailable");
            return log.line(&method, "FAIL proxy shutting down");
        }
        let mut cmd = self.command();
        let Ok(mut child) = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        else {
            reply(&mut client, "502 Bad Gateway");
            return log.line(&method, "FAIL curl did not start");
        };
        CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((std::ptr::from_ref(shutdown) as usize, child.id()));
        // Shutdown sets its flag before it kills: either it saw this PID, or
        // this load sees the flag.
        if shutdown.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = child.kill();
        }
        // Bounded, and drained so curl never blocks on a full pipe.
        let stderr = child.stderr.take().map(|e| {
            std::thread::spawn(move || {
                let mut e = e;
                let mut buf = Vec::new();
                let _ = e.by_ref().take(64 * 1024).read_to_end(&mut buf);
                let _ = std::io::copy(&mut e, &mut std::io::sink());
                buf
            })
        });
        let wrote = child
            .stdin
            .take()
            .is_some_and(|mut s| s.write_all(&config).is_ok());
        let status = match child.stdout.take() {
            Some(out) if wrote => relay(out, &mut client),
            _ => None,
        };
        CHILDREN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|&(_, p)| p != child.id());
        let _ = child.kill();
        let _ = child.wait();
        if let Some(code) = status {
            // A GET answered 405 is the MCP spec's "no standalone SSE stream",
            // which GitHub returns on every session: not an error.
            let expected = method == "GET" && code == "405";
            let verdict = if code.starts_with(['4', '5']) && !expected {
                "FAIL"
            } else {
                "FORWARDED"
            };
            log.line(&method, &format!("{verdict} {code}"));
        } else {
            reply(&mut client, "502 Bad Gateway");
            let err = stderr
                .and_then(|t| t.join().ok())
                .map(|b| redact_stderr(&b, self.token.expose()))
                .unwrap_or_default();
            log.line(&method, &format!("FAIL upstream: {}", err.trim()));
        }
    }
}

/// Copy curl's `-i` output to the client: the status line and headers, minus
/// hop-by-hop ones (curl has already de-chunked the body), then the body as it
/// arrives, unbuffered, so SSE streams through. Returns the status code once
/// the head is sent; `None` if curl produced no response.
fn relay(out: impl Read, client: &mut TcpStream) -> Option<String> {
    let mut out = BufReader::new(out);
    let mut status = String::new();
    out.read_line(&mut status).ok()?;
    let code = status.split_whitespace().nth(1)?.to_string();
    let mut head = status.trim_end().to_string() + "\r\n";
    loop {
        let mut line = String::new();
        if out.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let name = l.split(':').next().unwrap_or_default().to_ascii_lowercase();
        if !matches!(
            name.as_str(),
            "transfer-encoding" | "connection" | "keep-alive"
        ) {
            head += l;
            head += "\r\n";
        }
    }
    head += "Connection: close\r\n\r\n";
    if client.write_all(head.as_bytes()).is_ok() {
        // ponytail: a client that hangs up mid-stream is noticed on the next
        // upstream chunk, not at once; the session's exit reaps the rest.
        let _ = std::io::copy(&mut out, client);
    }
    let _ = client.shutdown(std::net::Shutdown::Both);
    Some(code)
}

/// Install a test endpoint with `upstream` (the real one is pinned).
#[cfg(test)]
pub(crate) fn install_for_test(upstream: &str, token: &str, secret: &str) -> Option<()> {
    let curl = crate::git::trusted_binary("curl")?;
    install_endpoint(Endpoint {
        token: SecretToken::new(token.into()),
        path: format!("/{secret}"),
        curl,
        upstream: upstream.into(),
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_detection() {
        for u in [
            "https://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/",
            "https://API.githubcopilot.com/mcp/readonly",
            "https://api.githubcopilot.com:443/mcp/readonly?x=1",
        ] {
            assert!(is_github_mcp_url(u), "{u}");
        }
        for u in [
            "http://api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com/mcp/x",
            "https://evil.example/api.githubcopilot.com/mcp",
            "https://api.githubcopilot.com.evil/mcp",
        ] {
            assert!(!is_github_mcp_url(u), "{u}");
        }
    }

    #[test]
    fn finds_entries_in_user_config_only() {
        let dir = tempfile::tempdir().unwrap();
        let oc = dir.path().join("oc");
        std::fs::create_dir(&oc).unwrap();
        std::fs::write(
            oc.join("opencode.jsonc"),
            r#"{ // c
              "mcp": {"servers": {"gh": {"type": "remote", "url": "https://api.githubcopilot.com/mcp/readonly"},
                                   "other": {"type": "remote", "url": "https://example.com/mcp"},}}}"#,
        )
        .unwrap();
        let file = dir.path().join("custom.json");
        std::fs::write(
            &file,
            r#"{"mcp":{"old":{"type":"remote","url":"https://api.githubcopilot.com/mcp/"}}}"#,
        )
        .unwrap();
        let content = r#"{"mcp":{"servers":{"gh2":{"url":"https://api.githubcopilot.com/mcp"}}}}"#;
        assert_eq!(
            configured_servers(&[oc], Some(&file), Some(content)),
            [
                (false, "old".to_string()),
                (true, "gh".to_string()),
                (true, "gh2".to_string())
            ]
        );
        // Nothing else is read: a project dir is not one of the inputs.
        assert_eq!(configured_servers(&[], None, None), []);
    }

    #[test]
    fn overlay_keeps_the_users_keys() {
        let existing = r#"{"model":"x","mcp":{"servers":{"gh":{"enabled":true,"headers":{"a":"b"}},"o":{"url":"u"}}}}"#;
        let gh = [(true, "gh".to_string())];
        let v: Value =
            serde_json::from_str(&overlay(Some(existing), &gh, "http://p").unwrap()).unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["mcp"]["servers"]["o"]["url"], "u");
        let e = &v["mcp"]["servers"]["gh"];
        assert_eq!(
            (
                e["url"].as_str(),
                e["oauth"].as_bool(),
                e["enabled"].as_bool()
            ),
            (Some("http://p"), Some(false), Some(true))
        );
        let fresh: Value = serde_json::from_str(&overlay(None, &gh, "http://p").unwrap()).unwrap();
        assert_eq!(fresh["mcp"]["servers"]["gh"]["type"], "remote");
        let old: Value =
            serde_json::from_str(&overlay(None, &[(false, "gh".into())], "http://p").unwrap())
                .unwrap();
        assert_eq!(
            (
                old["mcp"]["gh"]["oauth"].as_bool(),
                old["mcp"].get("servers")
            ),
            (Some(false), None)
        );
        assert_eq!(overlay(Some("[1]"), &gh, "http://p"), None);
        assert_eq!(overlay(Some("{\"mcp\":1}"), &gh, "http://p"), None);
    }

    fn hdrs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn config_pins_upstream_and_forces_headers() {
        let headers = hdrs(&[
            ("Authorization", "Bearer agent"),
            ("x-mcp-readonly", "false"),
            ("X-MCP-Lockdown", "false"),
            ("X-MCP-Toolsets", "repos"),
            ("Host", "evil"),
            ("Cookie", "c"),
            ("Mcp-Session-Id", "s\"1\\"),
        ]);
        let c = String::from_utf8(
            curl_config(UPSTREAM, None, "POST", &headers, b"{\"a\":\n1}", "T").unwrap(),
        )
        .unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines.iter().filter(|l| l.starts_with("url = ")).count(), 1);
        assert_eq!(lines[0], format!("url = \"{UPSTREAM}\""));
        assert!(!c.contains("agent") && !c.contains("Host:") && !c.contains("Cookie"));
        assert!(!c.to_lowercase().contains(": false"), "{c}");
        for h in [
            "Authorization: Bearer T",
            "X-MCP-Readonly: true",
            "X-MCP-Lockdown: true",
            "X-MCP-Toolsets: repos",
            r#"Mcp-Session-Id: s\"1\\"#,
        ] {
            assert!(c.contains(&format!("header = \"{h}\"")), "{h}: {c}");
        }
        assert!(c.contains(r#"data-raw = "{\"a\":\n1}""#));
        assert!(c.contains("noproxy = \"*\""), "{c}");
    }

    #[test]
    fn upstream_proxy_credential_and_tunnel_precede_the_body() {
        let via = UpstreamProxy::parse("http://u:p@127.0.0.1:3128").unwrap();
        let c =
            String::from_utf8(curl_config(UPSTREAM, Some(&via), "POST", &[], b"{}", "T").unwrap())
                .unwrap();
        assert!(c.contains("proxy = \"http://127.0.0.1:3128\""), "{c}");
        assert!(c.contains("noproxy = \"\""), "{c}");
        assert!(
            c.contains("proxy-header = \"Proxy-Authorization: Basic dTpw\""),
            "{c}"
        );
        let tunnel = c.find("proxytunnel\n").expect("no proxytunnel");
        assert!(tunnel < c.find("data-raw").unwrap(), "{c}");
    }

    /// The host env must not reach curl: proxy variables would reroute the
    /// token, and SSLKEYLOGFILE would write its TLS keys to disk.
    #[test]
    fn curl_runs_with_a_cleared_env_and_bounded_times() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("curl");
        let out = dir.path().join("env");
        std::fs::write(&fake, format!("#!/bin/sh\nenv > '{}'\n", out.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ep = Endpoint {
            token: SecretToken::new("T".into()),
            path: "/x".into(),
            curl: fake,
            upstream: UPSTREAM.into(),
        };
        let vars = [
            ("SSLKEYLOGFILE", Some("/keys")),
            ("HTTPS_PROXY", Some("http://trap")),
            ("SSL_CERT_FILE", Some("/ca.pem")),
        ];
        let mut cmd = temp_env::with_vars(vars, || ep.command());
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let joined = args.join(" ");
        assert!(
            joined.contains(&format!("--connect-timeout {CONNECT_TIMEOUT_SECS}")),
            "{joined}"
        );
        assert!(
            joined.contains(&format!("--max-time {MAX_TIME_SECS}")),
            "{joined}"
        );
        let status = temp_env::with_vars(vars, || cmd.stdin(Stdio::null()).status().unwrap());
        assert!(status.success());
        let env = std::fs::read_to_string(&out).unwrap();
        assert!(
            !env.contains("SSLKEYLOGFILE") && !env.contains("HTTPS_PROXY"),
            "{env}"
        );
        assert!(env.contains("SSL_CERT_FILE=/ca.pem"), "{env}");
    }

    #[test]
    fn no_curl_starts_after_shutdown() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("curl");
        let ran = dir.path().join("ran");
        std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", ran.display())).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let ep = Endpoint {
            token: SecretToken::new("T".into()),
            path: "/x".into(),
            curl: fake,
            upstream: UPSTREAM.into(),
        };
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        let log = Log {
            level: ProxyLogLevel::None,
            file: None,
        };
        let shut = std::sync::atomic::AtomicBool::new(true);
        ep.serve(
            server,
            b"GET /x HTTP/1.1\r\n\r\n",
            &log,
            None,
            std::time::Duration::from_secs(5),
            &shut,
        );
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 503"), "{reply:?}");
        assert_eq!(reply.matches("HTTP/1.1").count(), 1, "{reply:?}");
        assert!(!ran.exists(), "curl ran after shutdown");
    }

    #[test]
    fn huge_body_limit_does_not_overflow() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (mut server, _) = l.accept().unwrap();
        c.write_all(b"x").unwrap();
        assert!(read_body(&mut server, &mut [0], std::time::Duration::MAX));
    }

    #[test]
    fn kill_children_kills_only_that_proxy() {
        let spawn = || {
            #[allow(clippy::disallowed_methods)] // absolute path
            Command::new("/bin/sleep").arg("30").spawn().unwrap()
        };
        // Two proxies that could share a port: ownership is the flag, not the port.
        let (a, b) = (
            std::sync::atomic::AtomicBool::new(true),
            std::sync::atomic::AtomicBool::new(false),
        );
        let key = |f: &std::sync::atomic::AtomicBool| std::ptr::from_ref(f) as usize;
        let (mut mine, mut other) = (spawn(), spawn());
        CHILDREN
            .lock()
            .unwrap()
            .extend([(key(&a), mine.id()), (key(&b), other.id())]);
        kill_children(&a);
        assert!(!mine.wait().unwrap().success(), "the curl child survived");
        assert!(
            other.try_wait().unwrap().is_none(),
            "another proxy's child died"
        );
        let _ = other.kill();
        let _ = other.wait();
        CHILDREN
            .lock()
            .unwrap()
            .retain(|&(o, _)| o != key(&a) && o != key(&b));
    }

    #[test]
    fn log_line_escapes_control_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let log = Log {
            level: ProxyLogLevel::None,
            file: Some(path.clone()),
        };
        log.line("GET\r\n2099-01-01 POST", "OK\n\x1b[2K forged");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text:?}");
        assert!(!text.contains('\x1b') && !text.contains('\r'), "{text:?}");
    }

    #[test]
    fn control_bytes_in_headers_are_refused() {
        for (k, v) in [
            ("Mcp-Session-Id", "s\rurl = \"https://evil\""),
            ("Mcp-Session-Id", "s\nurl = \"https://evil\""),
            ("Mcp-Session-Id", "s\u{0}"),
            ("Mcp-Session-Id", "s\u{b}"),
            ("Mcp-Session-Id", "s\u{7f}"),
            ("X-A\r", "v"),
        ] {
            assert_eq!(
                curl_config(UPSTREAM, None, "POST", &hdrs(&[(k, v)]), b"", "T"),
                None,
                "{k:?}: {v:?}"
            );
        }
        assert!(curl_config(UPSTREAM, None, "POST", &hdrs(&[("A", "x\ty")]), b"", "T").is_some());
    }

    #[test]
    fn non_token_header_names_are_refused() {
        for k in [
            "@/etc/passwd",
            "@x",
            "",
            "X A",
            "X:A",
            "X;",
            "X\"A",
            "X(A)",
            "X\u{e9}",
        ] {
            assert_eq!(
                curl_config(UPSTREAM, None, "POST", &hdrs(&[(k, "v")]), b"", "T"),
                None,
                "{k:?}"
            );
        }
        let c = curl_config(
            UPSTREAM,
            None,
            "POST",
            &hdrs(&[("X-a!#$%&'*+.^_`|~1", "@v")]),
            b"",
            "T",
        );
        assert!(c.is_some());
    }

    #[test]
    fn stderr_is_redacted_before_truncation() {
        let token = "ghp_SECRETSECRETSECRET";
        let mut raw = vec![b'x'; 2040];
        raw.extend_from_slice(token.as_bytes());
        let out = redact_stderr(&raw, token);
        assert!(!out.contains("ghp_"), "{out}");
        assert!(out.len() <= 2048);
        assert!(redact_stderr(&[b'a'; 4000], token).len() == 2048);
    }
}
