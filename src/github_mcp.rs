//! GitHub's remote MCP server for OpenCode v2, through a host-side proxy (#797).
//!
//! GitHub's OAuth has no dynamic client registration, so OpenCode cannot log
//! in to `api.githubcopilot.com/mcp` itself, and cplt strips `GH_TOKEN` for
//! it. When the user's OpenCode config names that server, cplt starts a
//! listener on `127.0.0.1` and points the entry at it with `"oauth": false`.
//! The listener adds the host's gh token and forwards every request to one
//! fixed upstream, the read-only endpoint, with `X-MCP-Readonly` and
//! `X-MCP-Lockdown` forced on. The token never enters the sandbox through
//! this path; the agent gets a read-only, lockdown view of GitHub.
//!
//! cplt has no TLS stack, so the upstream leg runs through the system `curl`
//! (trusted dirs only), one process per request. The token and the request
//! reach curl on stdin as a config file, never in argv, and `-q` keeps the
//! user's `~/.curlrc` out. The listener path carries a random secret, so other
//! local processes cannot spend the token.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Map, Value};

use crate::proxy::ProxyLogLevel;

/// The only place requests go, whatever URL the user's entry names.
pub const UPSTREAM: &str = "https://api.githubcopilot.com/mcp/readonly";
const MAX_HEAD: usize = 64 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;

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

/// The GitHub MCP entries in the config OpenCode will load: the user's config
/// dir, `OPENCODE_CONFIG`, project files from `launch_dir` up to the repo
/// root, and `OPENCODE_CONFIG_CONTENT`. Project files are agent-writable, but
/// all they can do here is ask for the read-only proxy.
pub fn configured_servers(user_oc: &Path, launch_dir: &Path, content: Option<&str>) -> Vec<Entry> {
    let mut files: Vec<PathBuf> = ["config.json", "opencode.json", "opencode.jsonc"]
        .iter()
        .map(|f| user_oc.join(f))
        .collect();
    files.extend(std::env::var_os("OPENCODE_CONFIG").map(PathBuf::from));
    for dir in launch_dir.ancestors() {
        for f in [
            "opencode.json",
            "opencode.jsonc",
            ".opencode/opencode.json",
            ".opencode/opencode.jsonc",
        ] {
            files.push(dir.join(f));
        }
        if dir.join(".git").exists() {
            break;
        }
    }
    let mut texts: Vec<String> = files
        .iter()
        .filter_map(|f| {
            crate::untrusted::read_untrusted(f, CONFIG_LIMIT)
                .ok()
                .flatten()
        })
        .collect();
    texts.extend(content.map(str::to_string));
    let mut names: Vec<Entry> = texts
        .iter()
        .filter_map(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .flat_map(|v: Value| github_servers(&v))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// A running proxy: point OpenCode at `url`; the sandbox must allow `port`.
pub struct Proxy {
    pub port: u16,
    pub url: String,
}

/// Where request lines go: the proxy's log level and `--proxy-log` file.
#[derive(Clone)]
pub struct Log {
    pub level: ProxyLogLevel,
    pub file: Option<PathBuf>,
}

impl Log {
    fn line(&self, method: &str, status: &str) {
        let method = method.escape_debug().to_string();
        if self.level.should_log(status) {
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

/// Bind the listener and serve in the background for the life of the process.
pub fn start(token: String, log: Log) -> Result<Proxy, String> {
    let curl = crate::git::trusted_binary("curl").ok_or("no curl in the trusted dirs")?;
    serve(token, log, curl, UPSTREAM)
}

fn serve(token: String, log: Log, curl: PathBuf, upstream: &'static str) -> Result<Proxy, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let secret = crate::scratch::generate_session_id()?;
    let url = format!("http://127.0.0.1:{port}/{secret}");
    let path = format!("/{secret}");
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (token, log, curl, path) = (token.clone(), log.clone(), curl.clone(), path.clone());
            std::thread::spawn(move || handle(stream, &token, &log, &curl, &path, upstream));
        }
    });
    Ok(Proxy { port, url })
}

/// Client headers that never reach upstream: credentials and MCP mode
/// switches are cplt's to set; the rest are hop-by-hop or curl's job.
fn forwarded(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    !(n.starts_with("x-mcp-")
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

/// A quoted curl config value.
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

/// The curl config for one request. Upstream, credential and MCP mode come
/// from cplt alone; the client supplies only the method, its other headers
/// and the body.
fn curl_config(
    upstream: &str,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    token: &str,
) -> Vec<u8> {
    let mut c = Vec::new();
    let mut opt = |name: &str, value: &[u8]| {
        c.extend_from_slice(name.as_bytes());
        c.extend_from_slice(b" = ");
        quote(&mut c, value);
    };
    opt("url", upstream.as_bytes());
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
    if !body.is_empty() {
        opt("data-raw", body);
    }
    c
}

fn reply(stream: &mut TcpStream, status: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
}

/// One request per connection: read it, run curl, stream its answer back.
fn handle(mut stream: TcpStream, token: &str, log: &Log, curl: &Path, path: &str, upstream: &str) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half.take((MAX_HEAD + MAX_BODY) as u64));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let mut parts = line.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or_default().to_string(),
        parts.next().unwrap_or_default(),
    );
    if target != path {
        reply(&mut stream, "404 Not Found");
        return log.line(&method, "BLOCKED-PATH");
    }
    if !matches!(method.as_str(), "GET" | "POST" | "DELETE") {
        reply(&mut stream, "405 Method Not Allowed");
        return log.line(&method, "BLOCKED-METHOD");
    }
    let mut headers = Vec::new();
    let mut head = line.len();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || head > MAX_HEAD {
            reply(&mut stream, "400 Bad Request");
            return log.line(&method, "FAIL bad request");
        }
        head += line.len();
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    if header("transfer-encoding").is_some() {
        reply(&mut stream, "411 Length Required");
        return log.line(&method, "FAIL chunked request");
    }
    let len: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    if len > MAX_BODY || reader.read_exact(&mut body).is_err() || body.contains(&0) {
        reply(&mut stream, "400 Bad Request");
        return log.line(&method, "FAIL bad body");
    }

    #[allow(clippy::disallowed_methods)] // resolved trusted path, or a fixture in tests
    let mut cmd = Command::new(curl);
    // -q first: no ~/.curlrc. No redirects; https only for the real upstream.
    cmd.args([
        "-q",
        "-sS",
        "-N",
        "-i",
        "--http1.1",
        "--max-redirs",
        "0",
        "-K",
        "-",
    ]);
    if upstream.starts_with("https://") {
        cmd.args(["--proto", "=https"]);
    }
    let Ok(mut child) = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        reply(&mut stream, "502 Bad Gateway");
        return log.line(&method, "FAIL curl");
    };
    let config = curl_config(upstream, &method, &headers, &body, token);
    let wrote = child
        .stdin
        .take()
        .is_some_and(|mut s| s.write_all(&config).is_ok());
    let status = match child.stdout.take() {
        Some(out) if wrote => relay(out, &mut stream),
        _ => None,
    };
    let _ = child.kill();
    let _ = child.wait();
    if let Some(code) = status {
        log.line(&method, &format!("FORWARDED {code}"));
    } else {
        reply(&mut stream, "502 Bad Gateway");
        log.line(&method, "FAIL upstream");
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
    fn finds_entries_in_jsonc_and_content() {
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
        let project = dir.path().join("p");
        std::fs::create_dir_all(project.join(".git")).unwrap();
        let content = r#"{"mcp":{"servers":{"gh2":{"url":"https://api.githubcopilot.com/mcp"}}}}"#;
        assert_eq!(
            configured_servers(&oc, &project, Some(content)),
            [(true, "gh".to_string()), (true, "gh2".to_string())]
        );
        let legacy =
            r#"{"mcp":{"old":{"type":"remote","url":"https://api.githubcopilot.com/mcp/"}}}"#;
        assert_eq!(
            configured_servers(&project, &project, Some(legacy)),
            [(false, "old".to_string())]
        );
        assert!(configured_servers(&project, &project, None).is_empty());
    }

    #[test]
    fn overlay_keeps_the_users_keys() {
        let existing = r#"{"model":"x","mcp":{"servers":{"gh":{"enabled":true,"headers":{"a":"b"}},"o":{"url":"u"}}}}"#;
        let v: Value = serde_json::from_str(
            &overlay(Some(existing), &[(true, "gh".into())], "http://p").unwrap(),
        )
        .unwrap();
        assert_eq!(v["model"], "x");
        assert_eq!(v["mcp"]["servers"]["o"]["url"], "u");
        let gh = &v["mcp"]["servers"]["gh"];
        assert_eq!(
            (
                gh["url"].as_str(),
                gh["oauth"].as_bool(),
                gh["enabled"].as_bool()
            ),
            (Some("http://p"), Some(false), Some(true))
        );
        let fresh: Value =
            serde_json::from_str(&overlay(None, &[(true, "gh".into())], "http://p").unwrap())
                .unwrap();
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
        assert_eq!(
            overlay(Some("[1]"), &[(true, "gh".into())], "http://p"),
            None
        );
        assert_eq!(
            overlay(Some("{\"mcp\":1}"), &[(true, "gh".into())], "http://p"),
            None
        );
    }

    #[test]
    fn config_pins_upstream_and_forces_headers() {
        let headers = [
            ("Authorization", "Bearer agent"),
            ("x-mcp-readonly", "false"),
            ("X-MCP-Toolsets", "all"),
            ("Host", "evil"),
            ("Mcp-Session-Id", "s\"1\nurl = \"https://evil\""),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()));
        let c =
            String::from_utf8(curl_config(UPSTREAM, "POST", &headers, b"{\"a\":1}", "T")).unwrap();
        let lines: Vec<&str> = c.lines().collect();
        assert_eq!(lines.iter().filter(|l| l.starts_with("url = ")).count(), 1);
        assert_eq!(lines[0], format!("url = \"{UPSTREAM}\""));
        assert!(!c.contains("agent") && !c.contains("Toolsets") && !c.contains("evil\"\n"));
        assert!(!c.to_lowercase().contains("readonly: false") && !c.contains("Host:"));
        for h in [
            "Authorization: Bearer T",
            "X-MCP-Readonly: true",
            "X-MCP-Lockdown: true",
        ] {
            assert!(c.contains(&format!("header = \"{h}\"")), "{c}");
        }
        assert!(c.contains(r#"header = "Mcp-Session-Id: s\"1\nurl = \"https://evil\"""#));
        assert!(c.contains(r#"data-raw = "{\"a\":1}""#));
    }

    /// Crosses the real seam: a client request through the listener and the
    /// system curl to a fake upstream, which sees only what cplt allows.
    #[test]
    fn forwards_through_curl_to_a_fake_upstream() {
        let Some(curl) = crate::git::trusted_binary("curl") else {
            return;
        };
        let up = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream: &'static str = format!(
            "http://127.0.0.1:{}/mcp/readonly",
            up.local_addr().unwrap().port()
        )
        .leak();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (s, _) = up.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut req = String::new();
            loop {
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                req += &l;
                if l == "\r\n" {
                    break;
                }
            }
            let mut body = [0; 7];
            r.read_exact(&mut body).unwrap();
            tx.send((req, body)).unwrap();
            let mut s = s;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n7\r\ndata:1\n\r\n").unwrap();
            s.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));
            s.write_all(b"7\r\ndata:2\n\r\n0\r\n\r\n").unwrap();
        });
        let log = Log {
            level: ProxyLogLevel::None,
            file: None,
        };
        let p = serve("TOKEN".into(), log, curl, upstream).unwrap();
        let path = p
            .url
            .split_once(&format!(":{}", p.port))
            .unwrap()
            .1
            .to_string();

        let mut bad = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        bad.write_all(b"GET /mcp HTTP/1.1\r\n\r\n").unwrap();
        let mut resp = String::new();
        bad.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");

        let mut c = TcpStream::connect(("127.0.0.1", p.port)).unwrap();
        write!(
            c,
            "POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer agent\r\nX-MCP-Lockdown: false\r\n\
             Accept: text/event-stream\r\nContent-Length: 7\r\n\r\n{{\"a\":1}}"
        )
        .unwrap();
        let (req, body) = rx.recv().unwrap();
        let lower = req.to_lowercase();
        assert!(req.starts_with("POST /mcp/readonly HTTP/1.1"), "{req}");
        assert!(
            lower.contains("authorization: bearer token\r\n") && !lower.contains("bearer agent"),
            "{req}"
        );
        assert!(
            lower.contains("x-mcp-lockdown: true") && !lower.contains("lockdown: false"),
            "{req}"
        );
        assert!(
            lower.contains("x-mcp-readonly: true") && lower.contains("accept: text/event-stream"),
            "{req}"
        );
        assert_eq!(&body, b"{\"a\":1}");

        // The first event arrives before the upstream sends the second.
        let mut r = BufReader::new(c);
        let mut first = String::new();
        let started = std::time::Instant::now();
        while !first.contains("data:1") {
            r.read_line(&mut first).unwrap();
        }
        assert!(
            started.elapsed() < std::time::Duration::from_millis(250),
            "buffered"
        );
        assert!(
            first.starts_with("HTTP/1.1 200")
                && !first.to_lowercase().contains("transfer-encoding")
        );
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "data:2\n");
    }
}
